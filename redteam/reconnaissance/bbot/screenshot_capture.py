"""
Screenshot Capture Module - Red Team Edition
=============================================

Automated web screenshot capture for reconnaissance operations.
Supports multiple rendering engines with fallback options.

Features:
- Async screenshot capture using Playwright
- Fallback to Selenium/Chrome
- Full-page and viewport screenshots
- Custom viewport sizes
- JavaScript rendering wait
- Cookie/header injection
- Batch capture with rate limiting

Author: Apollo Red Team Toolkit
Version: 2.0.0
"""

import asyncio
import logging
import os
import hashlib
import re
from typing import List, Optional, Dict, Tuple
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Try to import Playwright
try:
    from playwright.async_api import async_playwright, Page, Browser, BrowserContext
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

# Try to import Selenium as fallback
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.chrome.service import Service
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False


@dataclass
class ScreenshotResult:
    """Container for screenshot result"""
    url: str
    path: Optional[str]
    success: bool
    error: Optional[str] = None
    title: Optional[str] = None
    status_code: Optional[int] = None
    final_url: Optional[str] = None
    capture_time: Optional[float] = None


class ScreenshotCapture:
    """
    Automated screenshot capture for web reconnaissance

    Supports:
    - Playwright (preferred): Fast, headless Chromium
    - Selenium (fallback): Chrome/Firefox WebDriver

    Features:
    - Batch capture with concurrency control
    - Full-page and viewport screenshots
    - Custom headers and cookies
    - JavaScript rendering wait
    """

    def __init__(
        self,
        output_dir: str,
        viewport_width: int = 1920,
        viewport_height: int = 1080,
        timeout: int = 30,
        max_concurrent: int = 5
    ):
        """
        Initialize screenshot capture

        Args:
            output_dir: Directory for screenshots
            viewport_width: Browser viewport width
            viewport_height: Browser viewport height
            timeout: Page load timeout in seconds
            max_concurrent: Maximum concurrent captures
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.viewport_width = viewport_width
        self.viewport_height = viewport_height
        self.timeout = timeout * 1000  # Convert to ms for Playwright
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)

        # Determine available engine
        if PLAYWRIGHT_AVAILABLE:
            self.engine = 'playwright'
            logger.info("Screenshot engine: Playwright")
        elif SELENIUM_AVAILABLE:
            self.engine = 'selenium'
            logger.info("Screenshot engine: Selenium (fallback)")
        else:
            self.engine = None
            logger.warning(
                "No screenshot engine available. "
                "Install playwright: pip install playwright && playwright install"
            )

    async def capture(
        self,
        urls: List[str],
        full_page: bool = False,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[List[Dict]] = None
    ) -> List[ScreenshotResult]:
        """
        Capture screenshots of multiple URLs

        Args:
            urls: List of URLs to capture
            full_page: Capture full page (scrolling)
            headers: Custom headers to inject
            cookies: Cookies to set

        Returns:
            List of ScreenshotResult objects
        """
        if not self.engine:
            logger.error("No screenshot engine available")
            return [
                ScreenshotResult(url=url, path=None, success=False, error="No engine available")
                for url in urls
            ]

        logger.info(f"Capturing {len(urls)} screenshots")
        start_time = datetime.now()

        if self.engine == 'playwright':
            results = await self._capture_playwright(urls, full_page, headers, cookies)
        else:
            results = await self._capture_selenium(urls, full_page, headers, cookies)

        duration = (datetime.now() - start_time).total_seconds()
        success_count = sum(1 for r in results if r.success)
        logger.info(f"Captured {success_count}/{len(urls)} screenshots in {duration:.2f}s")

        return results

    async def _capture_playwright(
        self,
        urls: List[str],
        full_page: bool,
        headers: Optional[Dict],
        cookies: Optional[List[Dict]]
    ) -> List[ScreenshotResult]:
        """Capture using Playwright"""
        results = []

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    '--no-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-gpu',
                    '--disable-web-security',
                    '--ignore-certificate-errors'
                ]
            )

            context = await browser.new_context(
                viewport={'width': self.viewport_width, 'height': self.viewport_height},
                ignore_https_errors=True,
                extra_http_headers=headers or {}
            )

            # Set cookies if provided
            if cookies:
                await context.add_cookies(cookies)

            # Capture with concurrency control
            tasks = [
                self._capture_page_playwright(context, url, full_page)
                for url in urls
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Handle exceptions
            final_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    final_results.append(ScreenshotResult(
                        url=urls[i],
                        path=None,
                        success=False,
                        error=str(result)
                    ))
                else:
                    final_results.append(result)

            await browser.close()

        return final_results

    async def _capture_page_playwright(
        self,
        context: "BrowserContext",
        url: str,
        full_page: bool
    ) -> ScreenshotResult:
        """Capture single page with Playwright"""
        async with self.semaphore:
            start_time = datetime.now()
            page = None

            try:
                page = await context.new_page()

                # Navigate to URL
                response = await page.goto(
                    url,
                    wait_until='networkidle',
                    timeout=self.timeout
                )

                # Wait for any dynamic content
                await page.wait_for_load_state('domcontentloaded')
                await asyncio.sleep(1)  # Additional wait for JS rendering

                # Generate filename
                filename = self._generate_filename(url)
                filepath = self.output_dir / filename

                # Capture screenshot
                await page.screenshot(
                    path=str(filepath),
                    full_page=full_page
                )

                # Get page info
                title = await page.title()
                final_url = page.url

                capture_time = (datetime.now() - start_time).total_seconds()

                return ScreenshotResult(
                    url=url,
                    path=str(filepath),
                    success=True,
                    title=title,
                    status_code=response.status if response else None,
                    final_url=final_url,
                    capture_time=capture_time
                )

            except Exception as e:
                logger.debug(f"Screenshot failed for {url}: {e}")
                return ScreenshotResult(
                    url=url,
                    path=None,
                    success=False,
                    error=str(e)
                )

            finally:
                if page:
                    await page.close()

    async def _capture_selenium(
        self,
        urls: List[str],
        full_page: bool,
        headers: Optional[Dict],
        cookies: Optional[List[Dict]]
    ) -> List[ScreenshotResult]:
        """Capture using Selenium (fallback)"""
        results = []

        options = ChromeOptions()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument('--ignore-certificate-errors')
        options.add_argument(f'--window-size={self.viewport_width},{self.viewport_height}')

        try:
            driver = webdriver.Chrome(options=options)
            driver.set_page_load_timeout(self.timeout // 1000)

            # Set cookies if provided
            if cookies:
                for cookie in cookies:
                    driver.add_cookie(cookie)

            for url in urls:
                result = await asyncio.to_thread(
                    self._capture_page_selenium, driver, url, full_page
                )
                results.append(result)

            driver.quit()

        except Exception as e:
            logger.error(f"Selenium initialization failed: {e}")
            # Return failure for all URLs
            for url in urls:
                if not any(r.url == url for r in results):
                    results.append(ScreenshotResult(
                        url=url,
                        path=None,
                        success=False,
                        error=str(e)
                    ))

        return results

    def _capture_page_selenium(
        self,
        driver,
        url: str,
        full_page: bool
    ) -> ScreenshotResult:
        """Capture single page with Selenium"""
        start_time = datetime.now()

        try:
            driver.get(url)

            # Wait for page load
            import time
            time.sleep(2)

            filename = self._generate_filename(url)
            filepath = self.output_dir / filename

            if full_page:
                # Get full page height
                total_height = driver.execute_script("return document.body.scrollHeight")
                driver.set_window_size(self.viewport_width, total_height)
                time.sleep(0.5)

            driver.save_screenshot(str(filepath))

            title = driver.title
            final_url = driver.current_url

            capture_time = (datetime.now() - start_time).total_seconds()

            return ScreenshotResult(
                url=url,
                path=str(filepath),
                success=True,
                title=title,
                final_url=final_url,
                capture_time=capture_time
            )

        except Exception as e:
            logger.debug(f"Selenium screenshot failed for {url}: {e}")
            return ScreenshotResult(
                url=url,
                path=None,
                success=False,
                error=str(e)
            )

    def _generate_filename(self, url: str) -> str:
        """Generate safe filename from URL"""
        # Create hash of URL for uniqueness
        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]

        # Clean URL for filename
        clean_url = re.sub(r'https?://', '', url)
        clean_url = re.sub(r'[^\w\-.]', '_', clean_url)
        clean_url = clean_url[:50]  # Limit length

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        return f"{clean_url}_{url_hash}_{timestamp}.png"

    async def capture_url(
        self,
        url: str,
        full_page: bool = False
    ) -> ScreenshotResult:
        """
        Capture single URL screenshot

        Args:
            url: URL to capture
            full_page: Capture full page

        Returns:
            ScreenshotResult
        """
        results = await self.capture([url], full_page=full_page)
        return results[0] if results else ScreenshotResult(
            url=url, path=None, success=False, error="Capture failed"
        )

    def list_screenshots(self) -> List[Dict]:
        """List all captured screenshots"""
        screenshots = []

        for filepath in self.output_dir.glob('*.png'):
            stat = filepath.stat()
            screenshots.append({
                'filename': filepath.name,
                'path': str(filepath),
                'size_bytes': stat.st_size,
                'created_at': datetime.fromtimestamp(stat.st_ctime).isoformat()
            })

        return sorted(screenshots, key=lambda x: x['created_at'], reverse=True)


# Convenience function
async def quick_screenshot(url: str, output_dir: str = '/tmp/screenshots') -> Optional[str]:
    """Quick screenshot capture"""
    capture = ScreenshotCapture(output_dir)
    result = await capture.capture_url(url)
    return result.path if result.success else None


if __name__ == '__main__':
    import sys

    async def main():
        if len(sys.argv) < 2:
            print("Usage: python screenshot_capture.py <url> [output_dir]")
            return

        url = sys.argv[1]
        output_dir = sys.argv[2] if len(sys.argv) > 2 else './screenshots'

        capture = ScreenshotCapture(output_dir)
        result = await capture.capture_url(url, full_page=True)

        if result.success:
            print(f"Screenshot saved: {result.path}")
            print(f"Title: {result.title}")
            print(f"Time: {result.capture_time:.2f}s")
        else:
            print(f"Failed: {result.error}")

    asyncio.run(main())
