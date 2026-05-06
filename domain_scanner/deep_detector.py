import asyncio
import re
from playwright.async_api import async_playwright

async def get_rendered_content(url):
    """
    Renders the page using a headless browser to capture dynamically loaded technologies.
    Returns rendered HTML, list of scripts, and global variable evidence.
    """
    results = {
        'html': '',
        'scripts': [],
        'variables': {},
        'error': None
    }
    
    try:
        async with async_playwright() as p:
            # Launch browser
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            )
            page = await context.new_page()
            
            # Listen for network requests to catch script loads
            def handle_request(request):
                if request.resource_type == 'script':
                    results['scripts'].append(request.url)
            
            page.on('request', handle_request)
            
            # Navigate and wait for network idle to catch tracking scripts
            try:
                await page.goto(url, wait_until='networkidle', timeout=30000)
            except Exception as e:
                # If networkidle fails, just continue with whatever we have
                print(f"DeepScan Warning: {url} timed out waiting for networkidle. Proceeding...")
            
            # Wait a bit more for late-loading trackers
            await asyncio.sleep(2)
            
            # Get rendered HTML
            results['html'] = await page.content()
            
            # Check for common tech global variables
            tech_vars = {
                'clarity': 'clarity',
                'google_tag_manager': 'google_tag_manager',
                'fbq': 'fbq',
                'hj': 'hj',
                'adobe': '_adobe_launch_initialized',
                'litHtml': 'litHtml',
                'core-js': '__core-js_shared__'
            }
            
            for key, var_name in tech_vars.items():
                try:
                    exists = await page.evaluate(f"typeof window.{var_name} !== 'undefined'")
                    if exists:
                        results['variables'][key] = True
                except:
                    pass
                    
            await browser.close()
            
    except Exception as e:
        results['error'] = str(e)
        print(f"DeepScan Critical Error: {str(e)}")
        
    return results

def run_deep_scan(url):
    """Sync wrapper for the async render function."""
    try:
        return asyncio.run(get_rendered_content(url))
    except Exception as e:
        return {'html': '', 'scripts': [], 'variables': {}, 'error': str(e)}
