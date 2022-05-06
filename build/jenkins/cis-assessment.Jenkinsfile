pipeline {

    options {
        timeout(time: 60, unit: 'MINUTES')
    }

    agent { label 'cis' }

    environment {
        ARTIFACTORY_APIKEY = credentials('artiifactory-baseimage-reader')
    }

    parameters {
        string name: 'BASE_IMAGE_URL', defaultValue: '', description: 'Artifactory base image URL'
    }

    stages {
        stage('Set up build tag') {
            steps {
                script {
                    currentBuild.displayName = "${BASE_IMAGE_URL}".split('/')[-1]
                }
            }
        }
        stage('Cleanup reports directory') {
            steps {
                dir('cis-reports') {
                    deleteDir()
                }
            }
        }
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        stage('Run CIS assessment') {
            steps {
                dir(path: 'jenkins') {
                    sh '/bin/bash ./cis-assessment.sh'
                }
            }
        }
    }

    post {
        success {
            archiveArtifacts artifacts: 'cis-reports/cis*.html'
        }
    }
}
