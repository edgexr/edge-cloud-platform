#!/usr/bin/env python3

import argparse
from datetime import datetime
import json
import os
import logging
import re
import redis
import requests
import subprocess
import sys

DEFAULT_GITLAB = "https://container-registry.mobiledgex.net"
DEFAULT_GCR_HOST = "eu.gcr.io"
GCP_SERVICE_ACCOUNT_FILE = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "/etc/gcloud.json")
GITLAB_TOKEN = os.getenv("GITLAB_TOKEN")
LOGLEVEL = logging.DEBUG if os.getenv("DEBUG") == "true" else logging.INFO

logging.basicConfig(format="%(asctime)-15s [%(levelname)s] %(message)s",
                    level=LOGLEVEL)

rconn = redis.Redis(host="localhost", decode_responses=True)

def api_request(args, api):
    url = "{0}/api/v4/{1}".format(args.gitlab, api)
    r = requests.get(url, headers={"PRIVATE-TOKEN": GITLAB_TOKEN})
    assert r.status_code == requests.codes.ok
    return r

def paged_response(args, api, per_page=100):
    next_page = None
    resp = []

    p_url = api + ('&' if '?' in api else '?')
    p_url += "per_page={0}".format(per_page)

    while True:
        url = p_url
        if next_page:
            url = "{0}&page={1}".format(p_url, next_page)
        r = api_request(args, url)
        resp.extend(r.json())

        logging.debug(r.headers)
        next_page = r.headers["X-Next-Page"]
        if not next_page:
            break

    return resp

def perc(x, y):
    return int((x * 100.0 / y) + .5)

def get_projects(args):
    projects = []
    for project in paged_response(args, "projects?simple=true"):
        projects.append({
            "id": project["id"],
            "name": project["path_with_namespace"],
        })

    return projects

def get_images_for_projects(args, projects):
    images = []
    nprojects = len(projects)

    for idx, project in enumerate(projects):
        if idx and idx % 5 == 0:
            logging.info("Loaded {0} of {1} projects ({2}% done)".format(
                idx, nprojects, perc(idx, nprojects)))

        api = "projects/{0}/registry/repositories".format(project["id"])
        for repo in paged_response(args, api):
            tagapi = api + "/{0}/tags".format(repo["id"])
            for tag in paged_response(args, tagapi):
                tagdet = api_request(args, tagapi + "/" + tag["name"]).json()
                images.append({
                    "name": tag["name"],
                    "image": tag["location"],
                    "digest": tagdet["digest"],
                })

    return images

def backup_images(args, images):
    errors = []
    datestamp = datetime.now().strftime("%Y-%m-%d")
    nimages = len(images)
    nnew = 0
    for idx, imgdet in enumerate(images):
        image = imgdet["image"]
        digest = imgdet["digest"]
        gl_image = image

        if idx and idx % 5 == 0:
            logging.info("Backed up {0} of {1} images ({2}% done)".format(
                idx, nimages, perc(idx, nimages)))

        try:
            path = re.sub(r'^[^/]*/', '', image)
            assert path != image

            nimage = "/".join([args.gcr_host, args.gcp_project, datestamp, path])

            # Check if image is already present in GCR
            rkey = "glbk_{0}".format(digest)
            rval = rconn.get(rkey)
            if rval:
                logging.debug("Source image already in GCR: " + rval)
                image = rval

            if image != gl_image:
                if image == nimage:
                    logging.info("Destination image already present: " + nimage)
                    continue

                # Image already in GCR; attempt to retag it
                if args.dry_run:
                    logging.info("Would have re-tagged {0} as {1}".format(image, nimage))
                else:
                    logging.info("Re-tagging {0} as {1}".format(image, nimage))
                    try:
                        subprocess.check_call(["gcloud",
                                               "--account={0}".format(args.service_account),
                                               "--quiet",
                                               "container",
                                               "images",
                                               "add-tag",
                                               image,
                                               nimage])
                        continue
                    except Exception as e:
                        logging.exception("Failed to retag GCR image: {0} to {1}".format(
                            image, nimage))
                        # Fall back to downloading from Gitlab

            # Download image from Gitlab and upload to GCR
            if args.dry_run:
                logging.info("Would have backed up {0} to {1}".format(image, nimage))
            else:
                logging.info("Backing up {0} to {1}".format(image, nimage))
                pargs = {}
                if not args.verbose:
                    pargs["stdout"] = subprocess.DEVNULL
                subprocess.check_call(["docker", "pull", image], **pargs)
                subprocess.check_call(["docker", "tag", image, nimage], **pargs)
                subprocess.check_call(["docker", "push", nimage], **pargs)

                try:
                    logging.debug("Removing image: " + image)
                    subprocess.check_call(["docker", "image", "rm", image], **pargs)

                    logging.debug("Removing image: " + nimage)
                    subprocess.check_call(["docker", "image", "rm", nimage], **pargs)
                except Exception as e:
                    logging.exception("Failed to clean up image: " + image)

                logging.debug("Recording tag: {0}: {1}".format(rkey, image))
                rconn.set(rkey, nimage)

                nnew += 1

        except Exception as e:
            logging.exception("Failed to back up image: " + image)
            errors.append(image)

    if errors:
        logging.warning("Failed to back up images:\n - " + "\n - ".join(images))

    logging.info("New images: {0}".format(nnew))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--gitlab", "-g", help="Gitlab instance",
                        default=DEFAULT_GITLAB)
    parser.add_argument("--gcr-host", "-o", help="GCR host to back up to",
                        default=DEFAULT_GCR_HOST)
    parser.add_argument("--gcp-project", "-p", help="GCP project ID")
    parser.add_argument("--service-account", "-s", help="GCP service account file")
    parser.add_argument("--dry-run", "-n", help="Do not actually backup images",
                        action="store_true")
    parser.add_argument("--verbose", "-v", help="Verbose messages",
                        action="store_true")
    args = parser.parse_args()

    if not GITLAB_TOKEN:
        sys.exit("GITLAB_TOKEN environment variable not set")

    if not args.gcp_project:
        p = subprocess.Popen(["gcloud", "config", "get-value", "project"],
                             stdout=subprocess.PIPE, universal_newlines=True)
        out, err = p.communicate()
        out = out.strip()
        assert len(out) > 0
        args.gcp_project = out

    if not args.service_account:
        with open(GCP_SERVICE_ACCOUNT_FILE) as f:
            acc = json.load(f)
            args.service_account = acc["client_email"]

    p = get_projects(args)
    i = get_images_for_projects(args, p)
    backup_images(args, i)
