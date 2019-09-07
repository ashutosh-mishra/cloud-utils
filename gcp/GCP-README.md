Steps to run the script:

1. Create a virtualenv
virtualenv venv

2. Activate virtual env
source venv/bin/activate

3. Install dependencies
pip install -r requirements.txt

4. Run the script
python delete_stale_nws.py --project test-proj-195802 --creds-file creds.json --networks n1 n2 n3 n4

