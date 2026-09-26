import httpx
import asyncio

async def test_osv():
    async with httpx.AsyncClient() as client:
        # Purl payload
        payload_purl = {
            "queries": [{"package": {"purl": "pkg:npm/lodash@4.0.0"}}]
        }
        # Name/eco payload
        payload_name = {
            "queries": [{"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.0.0"}]
        }
        
        r1 = await client.post("https://api.osv.dev/v1/querybatch", json=payload_purl)
        print("PURL Results:", len(r1.json().get('results', [])[0].get('vulns', [])))
        
        r2 = await client.post("https://api.osv.dev/v1/querybatch", json=payload_name)
        print("NAME/ECO Results:", len(r2.json().get('results', [])[0].get('vulns', [])))

asyncio.run(test_osv())
