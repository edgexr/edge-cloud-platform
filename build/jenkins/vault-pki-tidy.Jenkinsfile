pipeline {
    options {
        timeout(time: 10, unit: 'MINUTES')
    }
    agent any
    environment {
        main_VAULT_ROLE = credentials('main-vault-pki-tidy-role')
        stage_VAULT_ROLE = credentials('staging-vault-pki-tidy-role')
        qa_VAULT_ROLE = credentials('qa-vault-pki-tidy-role')
        dev_VAULT_ROLE = credentials('dev-vault-pki-tidy-role')
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
for DEPLOY_ENVIRON in main stage qa dev; do
    eval "VAULT_ROLE_ID=\\\$${DEPLOY_ENVIRON}_VAULT_ROLE_USR"
    eval "VAULT_SECRET_ID=\\\$${DEPLOY_ENVIRON}_VAULT_ROLE_PSW"
    export VAULT_ADDR="https://vault-${DEPLOY_ENVIRON}.mobiledgex.net"
    VAULT_TOKEN=$( vault write -format=json auth/approle/login role_id="$VAULT_ROLE_ID" secret_id="$VAULT_SECRET_ID" \
	    | jq -r .auth.client_token )
    export VAULT_TOKEN

    for PKI in pki pki-global pki-regional pki-regional-cloudlet; do
        vault write ${PKI}/tidy tidy_cert_store=true tidy_revoked_certs=true
    done

    unset VAULT_TOKEN
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
