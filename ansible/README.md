## Set up the environment

* Set up a virtual environement for Ansible
  ```
  python3 -m venv ~/venv/ansible
  . ~/venv/ansible/bin/activate
  pip install --upgrade pip
  ```
* Install dependencies
  ```
  cd edge-cloud-infra/ansible

  . ~/venv/ansible/bin/activate
  pip install -r requirements.txt
  ```

## Examples

### Create or update the mexplat staging environment

```bash
cd edge-cloud-infra/terraform/mexplat/stage
make plan
make deploy
```

### Update the mexplat staging environment to version "2019-05-06"

```bash
cd edge-cloud-infra/ansible
./deploy -V 2020-04-10 staging
```
