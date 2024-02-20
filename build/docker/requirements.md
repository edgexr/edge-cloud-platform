## How to create requirements file
Set up and enter virtual env
```bash
pip install --user virtualenv
python3 -m venv env
source env/bin/activate
```
Install packages and freeze
```bash
pip install python-openstackclient
pip install ujson
pip freeze > requirements-infra.txt
```
Leave virtual env
```bash
deactivate
```
