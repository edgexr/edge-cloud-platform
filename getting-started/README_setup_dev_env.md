MobiledgeX Development Setup Procedure

   - setup_dev_env.sh sets up your environment on your macbook locally.
   - It essentially automates the steps on 'Getting Started' Confluence page (https://mobiledgex.atlassian.net/wiki/spaces/SWDEV/pages/22478869/Getting+Started)


Make sure your git setup is working.
   - you have a git account (aka GITHUB_ID) that is linked to mobilegex github account.
       * You have to provide your GITHUB_ID to Sunay to link it to MobiledgeX github account. 
   - you have git personal token setup. Getting Started page has instructions.


Run following commands from a terminal on your macbook:

   mkdir -p ~/go/src/github.com/mobiledgex/
   git clone https://github.com/mobiledgex/edge-cloud-infra.git
   cd getting-started
   ./setup_dev_env.sh
  

