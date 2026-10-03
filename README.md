# Free OSINT transforms for Maltego

Passive, keyless transforms built on the official maltego-trx SDK.

## Connect this set to Maltego from GitHub

```
git clone https://github.com/larrycameron80/maltego-free-osint.git
cd maltego-free-osint
pip install -r requirements.txt
python project.py list
```

In Maltego: Transforms, New Local Transform Set. Command:

```
python project.py local <name>
```

Working directory is the cloned repo. Maltego appends the entity value. `domaintogithub` searches public users and repositories. No GitHub token is required; the public API is rate limited.

`python project.py runserver` then open http://localhost:8080/ui for the same feeds in a browser.

`transforms.csv` is the iTDS import. Public Transform Hub listing still needs a Maltego partner account.
