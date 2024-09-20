#!/bin/bash
sed -i -E -e 's|(Id)(.+)(json:"_id)|Uid\2\3|g' osm-generated.go
