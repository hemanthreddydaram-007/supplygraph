from app.models.core import PURL, Ecosystem
p = PURL(ecosystem=Ecosystem.NPM, name="lodash", version="4.0.0")
print("Canonical:", p.canonical)
