pipeline {
    options {
        timeout(time: 30, unit: 'MINUTES')
    }
    agent any
    parameters {
        string(name: 'DOCKER_BUILD_TAG', defaultValue: '', description: 'Docker build tag; defaults to date stamp')
    }
    environment {
        PAGERDUTY_INTEGRATION_KEY = credentials('pagerduty-service-integration-key')
        DOCKER_BUILD_TAG = """${sh(
            returnStdout: true,
            script: '''
                if [ -n "$DOCKER_BUILD_TAG" ]; then
                    echo -n "$DOCKER_BUILD_TAG"
                else
                    date +"%Y-%m-%d" | tr -d "\n"
                fi
            '''
        )}"""
    }
    stages {
        stage('Set up build tag') {
            steps {
                script {
                    currentBuild.displayName = "${DOCKER_BUILD_TAG}"
                }
            }
        }
        stage('Checkout') {
            steps {
                dir(path: 'go/src/github.com/mobiledgex/edge-cloud-infra') {
                    checkout scm
                }
                dir(path: 'go/src/github.com/mobiledgex/edge-cloud') {
                    git url: 'git@github.com:mobiledgex/edge-cloud.git'
                }
                dir(path: 'go/src/github.com/mobiledgex/edge-proto') {
                    git url: 'git@github.com:mobiledgex/edge-proto.git'
                }
            }
        }
        stage('Edge-Cloud Version') {
            steps {
                dir(path: 'go/src/github.com/mobiledgex/edge-cloud-infra') {
                    sh label: 'make edge-cloud-version-set', script: '''$!/bin/bash
export PATH=$PATH:$HOME/go/bin:$WORKSPACE/go/bin
export GOPATH=$WORKSPACE/go
make edge-cloud-version-set
                    '''
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
                    sh label: 'make build-nightly', script: '''#!/bin/bash
TAG="${DOCKER_BUILD_TAG}" make build-nightly
                    '''
                }
                script {
                    currentBuild.displayName = sh(returnStdout: true,
                        script: "docker run --rm harbor.mobiledgex.net/mobiledgex/edge-cloud:${DOCKER_BUILD_TAG} version")
                }
            }
        }
        stage('Swagger Upload') {
            steps {
                sh 'docker run --rm harbor.mobiledgex.net/mobiledgex/edge-cloud:${DOCKER_BUILD_TAG} dump-docs internal >internal.json'
                sh 'docker run --rm harbor.mobiledgex.net/mobiledgex/edge-cloud:${DOCKER_BUILD_TAG} dump-docs external >external.json'
                rtUpload (
                    serverId: "artifactory",
                    spec:
                        """{
                            "files": [
                                {
                                    "pattern": "internal.json",
                                    "target": "build-artifacts/swagger-spec/${DOCKER_BUILD_TAG}/apidocs.swagger.json"
                                }
                            ]
                        }"""
                )
                rtUpload (
                    serverId: "artifactory",
                    spec:
                        """{
                            "files": [
                                {
                                    "pattern": "external.json",
                                    "target": "build-artifacts/swagger-spec/${DOCKER_BUILD_TAG}/external/apidocs.swagger.json"
                                }
                            ]
                        }"""
                )
            }
        }
    }
    post {
        success {
            slackSend color: 'good', message: "Build Successful - ${env.JOB_NAME} #${env.BUILD_NUMBER} (<${env.RUN_DISPLAY_URL}|Open>)"
            pagerduty(resolve: true,
                      serviceKey: "${PAGERDUTY_INTEGRATION_KEY}",
                      incidentKey: "jenkins-${env.JOB_NAME}",
                      incDescription: "Build Successful - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                      incDetails: "${env.RUN_DISPLAY_URL}")
        }
        failure {
            slackSend color: 'warning', message: "Build Failed - ${env.JOB_NAME} #${env.BUILD_NUMBER} (<${env.RUN_DISPLAY_URL}|Open>)"
            pagerduty(resolve: false,
                      serviceKey: "${PAGERDUTY_INTEGRATION_KEY}",
                      incidentKey: "jenkins-${env.JOB_NAME}",
                      incDescription: "Build Failure - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                      incDetails: "${env.RUN_DISPLAY_URL}")
        }
    }
}
