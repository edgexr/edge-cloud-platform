pipeline {
    options {
        timeout(time: 30, unit: 'MINUTES')
    }
    agent any
    parameters {
        string(name: 'BRANCH', defaultValue: '', description: 'Branch or tag to build')
        string(name: 'DOCKER_BUILD_TAG', defaultValue: '', description: 'Docker build tag for the custom build')
    }
    environment {
        DEFAULT_DOCKER_BUILD_TAG = """${sh(
            returnStdout: true,
            script: '''
            echo -n "${BRANCH}-`date +'%Y-%m-%d'`"
            '''
        )}"""
    }
    stages {
        stage('Set up build tag') {
            steps {
                script {
                    try {
                        currentBuild.displayName = "${DOCKER_BUILD_TAG}"
                    } catch (err) {
                        currentBuild.displayName = "${DEFAULT_DOCKER_BUILD_TAG}"
                    }
                }
            }
        }
        stage('Clean') {
            steps {
                deleteDir()
            }
        }
        stage('Checkout') {
            steps {
                dir(path: 'go/src/github.com/mobiledgex/edge-cloud-infra') {
                    checkout([$class: 'GitSCM',
                             branches: [[name: "${BRANCH}"]],
                             userRemoteConfigs: [[refspec: '+refs/remotes/origin/*:refs/tags/*',
                                      url: 'git@github.com:mobiledgex/edge-cloud-infra.git']]
                            ])
                }
                dir(path: 'go/src/github.com/mobiledgex/edge-cloud') {
                    checkout([$class: 'GitSCM',
                             branches: [[name: "${BRANCH}"]],
                             userRemoteConfigs: [[refspec: '+refs/remotes/origin/*:refs/tags/*',
                                      url: 'git@github.com:mobiledgex/edge-cloud.git']]
                            ])
                }
                dir(path: 'go/src/github.com/mobiledgex/edge-proto') {
                    checkout([$class: 'GitSCM',
                             branches: [[name: "${BRANCH}"]],
                             userRemoteConfigs: [[refspec: '+refs/remotes/origin/*:refs/tags/*',
                                      url: 'git@github.com:mobiledgex/edge-proto.git']]
                            ])
                }
            }
        }
        stage('Force Clean') {
            steps {
                dir(path: 'go/src/github.com/mobiledgex/edge-cloud') {
                    sh label: 'git clean edge-cloud', script: 'git clean -f -d -x'
                }
                dir(path: 'go/src/github.com/mobiledgex/edge-cloud-infra') {
                    sh label: 'git clean edge-cloud-infra', script: 'git clean -f -d -x'
                }
            }
        }
        stage('Docker Image') {
            steps {
                dir(path: 'go/src/github.com/mobiledgex/edge-cloud') {
                    sh label: 'make build-docker', script: '''#!/bin/bash
[ -n "$DOCKER_BUILD_TAG" ] || DOCKER_BUILD_TAG="$DEFAULT_DOCKER_BUILD_TAG"
TAG="${DOCKER_BUILD_TAG}" REGISTRY=harbor.mobiledgex.net/mobiledgex make build-docker
                    '''
                }
                script {
                    currentBuild.displayName = sh returnStdout: true,
                        script: '''#!/bin/bash
[ -n "$DOCKER_BUILD_TAG" ] || DOCKER_BUILD_TAG="$DEFAULT_DOCKER_BUILD_TAG"
docker run --rm harbor.mobiledgex.net/mobiledgex/edge-cloud:${DOCKER_BUILD_TAG} version
                    '''
                }
            }
        }
    }
    post {
        success {
            slackSend color: 'good', message: "Build Successful - ${env.JOB_NAME} #${env.BUILD_NUMBER} (<${env.RUN_DISPLAY_URL}|Open>)"
        }
        failure {
            slackSend color: 'warning', message: "Build Failed - ${env.JOB_NAME} #${env.BUILD_NUMBER} (<${env.RUN_DISPLAY_URL}|Open>)"
        }
    }
}
