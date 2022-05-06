pipeline {

    options {
        timeout(time: 5, unit: 'MINUTES')
    }
    agent any

    environment {
        BUILD_TAG = sh(returnStdout: true, script: 'date +"%Y-%m-%d" | tr -d "\n"')
        PAGERDUTY_INTEGRATION_KEY = credentials('pagerduty-service-integration-key')
    }

    stages {
        stage('Set up build tag') {
            steps {
                script {
                    currentBuild.displayName = "${BUILD_TAG}"
                }
            }
        }
        stage('Checkout') {
            steps {
                dir(path: 'edge-cloud-sdk-csharp') {
                    git url: 'git@github.com:mobiledgex/edge-cloud-sdk-csharp.git'
                }
            }
        }
        stage('Generate docs') {
            steps {
                dir(path: 'edge-cloud-sdk-csharp/rest') {
                    sh 'make generate-doxygen'
                }
            }
        }
        stage('Upload to Artifactory') {
            steps {
                dir(path: 'edge-cloud-sdk-csharp/rest/Doxygen') {
                    rtUpload (
                        serverId: "artifactory",
                        spec:
                            """{
                                "files": [
                                    {
                                        "pattern": "html.zip",
                                        "target": "apidocs/edge-cloud-sdk-csharp/${BUILD_TAG}/html.zip"
                                    }
                                ]
                            }"""
                    )
                }
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
