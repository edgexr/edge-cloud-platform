pipeline {
    options {
        timeout(time: 10, unit: 'MINUTES')
    }
    agent any
    environment {
        ANSIBLE_VAULT_PASSWORD_FILE = credentials('ansible-mex-vault-pass-file')
        ARM_ACCESS_KEY = credentials('azure-storage-access-key')
        staging_ANSIBLE_ROLE = credentials('staging-vault-ansible-role')
        mexdemo_ANSIBLE_ROLE = credentials('mexdemo-vault-ansible-role')
        PAGERDUTY_INTEGRATION_KEY = credentials('pagerduty-service-integration-key')
    }
    stages {
        stage('Backup') {
            steps {
                dir(path: 'ansible') {
                    ansiColor('xterm') {
                        sh label: 'Run ansible playbook', script: '''$!/bin/bash
set -e
export ANSIBLE_FORCE_COLOR=true
for DEPLOY_ENVIRON in mexdemo staging; do
    eval export "VAULT_ROLE_ID=\\\$${DEPLOY_ENVIRON}_ANSIBLE_ROLE_USR"
    eval export "VAULT_SECRET_ID=\\\$${DEPLOY_ENVIRON}_ANSIBLE_ROLE_PSW"
    ./deploy.sh -p etcd-backup.yml -G -y "$DEPLOY_ENVIRON"
done
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
