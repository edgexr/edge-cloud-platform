pipeline {
    options {
        timeout(time: 30, unit: 'MINUTES')
    }
    agent any
    environment {
        ANSIBLE_ROLE = credentials('staging-vault-ansible-role')
        GITHUB_CREDS = credentials('ansible-github-credentials')
        PAGERDUTY_INTEGRATION_KEY = credentials('pagerduty-service-integration-key')
        TAG = "${params.TAG}"
    }
    parameters {
        string name: 'TAG', defaultValue: 'latest', description: 'Console version (tag) to deploy'
        booleanParam name: 'DO_DEPLOY', defaultValue: false, description: 'Flag to control if deployment is actually attempted'
    }
    stages {
        stage('Set up build tag') {
            steps {
                script {
                    currentBuild.displayName = "${params.TAG}"
                }
            }
        }
        stage('Deploy') {
            steps {
                dir(path: 'ansible') {
                    ansiColor('xterm') {
                        sh label: 'Run ansible playbook', script: '''#!/bin/bash
export ANSIBLE_FORCE_COLOR=true
export GITHUB_USER="${GITHUB_CREDS_USR}"
export GITHUB_TOKEN="${GITHUB_CREDS_PSW}"
export VAULT_ROLE_ID="${ANSIBLE_ROLE_USR}"
export VAULT_SECRET_ID="${ANSIBLE_ROLE_PSW}"

if ! $DO_DEPLOY; then
        echo "Skipping the staging deployment"
        exit 0
fi

CMD=( ./deploy.sh -y -s setup,mc )
[[ "$TAG" != "latest" ]] && CMD+=( -C ${TAG} )
"${CMD[@]}" staging console
                        '''
                    }
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
