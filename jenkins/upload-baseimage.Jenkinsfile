pipeline {

    options {
        timeout(time: 90, unit: 'MINUTES')
    }

    agent { label 'cis' }

    environment {
        ARTIFACTORY_APIKEY = credentials('artiifactory-baseimage-reader')
        PAGERDUTY_INTEGRATION_KEY = credentials('pagerduty-service-integration-key')
        BASE_IMAGE_ARTF_PATH = 'https://artifactory.mobiledgex.net/artifactory/baseimages'
    }

    parameters {
        string name: 'OPENSTACK_INSTANCE', defaultValue: 'beacon', description: 'Openstack instance holding the image (Example: beacon)'
        string name: 'BASE_IMAGE_NAME', defaultValue: '', description: 'Example: mobiledgex-v4.3.5'
    }

    stages {
        stage('Set up build tag') {
            steps {
                script {
                    currentBuild.displayName = "${BASE_IMAGE_NAME}"
                }
            }
        }
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        stage('Compress and upload image') {
            steps {
                dir(path: 'jenkins') {
                    sh '/bin/bash ./upload-baseimage.sh'
                }
            }
        }
        stage('Run CIS-CAT assessment') {
            steps {
                build job: 'cis-cat-assessment',
                      parameters: [[$class: 'StringParameterValue',
                                    name: 'BASE_IMAGE_URL',
                                    value: "${BASE_IMAGE_ARTF_PATH}/${BASE_IMAGE_NAME.replaceAll('_uncompressed', '')}.qcow2"]],
                      propagate: false,
                      wait: false
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
