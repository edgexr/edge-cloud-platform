pipeline {
    options {
        timeout(time: 30, unit: 'MINUTES')
    }
    agent any
    environment {
        main_VAULT_ROLE = credentials('main-vault-snapshot-role')
        stage_VAULT_ROLE = credentials('staging-vault-snapshot-role')
        qa_VAULT_ROLE = credentials('qa-vault-snapshot-role')
        dev_VAULT_ROLE = credentials('dev-vault-snapshot-role')
        ARTIFACTORY_ACCESS_TOKEN = credentials('artifactory-vault-backup-token')
        PAGERDUTY_INTEGRATION_KEY = credentials('pagerduty-service-integration-key')
    }
    stages {
        stage('Backup') {
            steps {
                sh label: 'Backup vault', script: '''$!/bin/bash
set -e
export ANSIBLE_FORCE_COLOR=true
for DEPLOY_ENVIRON in main stage qa dev; do
    eval "VAULT_ROLE_ID=\\\$${DEPLOY_ENVIRON}_VAULT_ROLE_USR"
    eval "VAULT_SECRET_ID=\\\$${DEPLOY_ENVIRON}_VAULT_ROLE_PSW"

    VAULT_ROLE_ID=${VAULT_ROLE_ID} VAULT_SECRET_ID=${VAULT_SECRET_ID} \
        jenkins/vault-backup.py ${DEPLOY_ENVIRON}
done
                        '''
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
