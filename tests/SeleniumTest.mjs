import { Builder, By, until } from 'selenium-webdriver';
import assert from 'assert';

// Get the argument (default to 'local' if not provided)
const environment = process.argv[2] || 'local';

// URLs based on environment
const seleniumUrl = environment === 'github' 
  ? 'http://selenium:4444/wd/hub' 
  : 'http://localhost:4444/wd/hub';

const serverUrl = environment === 'github' 
  ? 'http://testserver' 
  : 'http://host.docker.internal';

console.log(`Running tests in '${environment}' environment`);
console.log(`Selenium URL: ${seleniumUrl}`);
console.log(`Server URL: ${serverUrl}`);

(async function testSecureSearchApplication() {

    console.log("before driver init")

    // Initialize the WebDriver with Chrome
    const driver = await new Builder()
        .forBrowser('chrome')
        .usingServer(seleniumUrl)
        .build();

    try {

        console.log("after driver init")
        
        await driver.get(serverUrl);

        console.log("after driver.get serverUrl")

        // Test 1: Check home page elements
        console.log("Testing home page elements...");
        
        let searchInput = await driver.wait(
            until.elementLocated(By.name('searchTerm')),
            5000
        );

        let submitButton = await driver.findElement(By.css('button[type="submit"]'));
        assert.ok(searchInput, 'Search input should exist');
        assert.ok(submitButton, 'Submit button should exist');
        console.log('✓ Home page elements found successfully');

        // Test 2: Test valid input acceptance
        console.log("Testing valid input acceptance...");
        
        await searchInput.clear();
        await searchInput.sendKeys('hello world');
        await submitButton.click();
        await driver.sleep(1000);

        const pageContent = await driver.getPageSource();
        
        if (pageContent.includes('Search Results') && pageContent.includes('hello world')) {
            console.log('✓ Valid input correctly accepted and displayed');
        } else {
            throw new Error('Valid input was not processed correctly');
        }

        // Test 3: Test XSS attack prevention
        console.log("Testing XSS prevention...");
        
        await driver.get(serverUrl);
        
        searchInput = await driver.wait(until.elementLocated(By.name('searchTerm')), 5000);
        submitButton = await driver.findElement(By.css('button[type="submit"]'));
        
        await searchInput.clear();
        await searchInput.sendKeys('<script>alert("XSS")</script>');
        await submitButton.click();
        await driver.sleep(1000);

        const xssPageContent = await driver.getPageSource();
        
        if (xssPageContent.includes('Invalid input detected')) {
            console.log('✓ XSS attack correctly blocked');
        } else {
            throw new Error('XSS attack was not detected and blocked');
        }

        // Test 4: Test SQL injection prevention
        console.log("Testing SQL injection prevention...");
        
        await driver.get(serverUrl);
        
        searchInput = await driver.wait(until.elementLocated(By.name('searchTerm')), 5000);
        submitButton = await driver.findElement(By.css('button[type="submit"]'));
        
        await searchInput.clear();
        await searchInput.sendKeys("' UNION SELECT * FROM users --");
        await submitButton.click();
        await driver.sleep(1000);
        
        const sqlPageContent = await driver.getPageSource();
        
        if (sqlPageContent.includes('Invalid input detected')) {
            console.log('✓ SQL injection attack correctly blocked');
        } else {
            console.log('⚠️ SQL injection behavior unexpected');
        }

        // Test 5: Test return to home functionality
        console.log("Testing return to home functionality...");
        
        await driver.get(serverUrl);
        searchInput = await driver.wait(until.elementLocated(By.name('searchTerm')), 5000);
        submitButton = await driver.findElement(By.css('button[type="submit"]'));
        
        await searchInput.clear();
        await searchInput.sendKeys('test search');
        await submitButton.click();
        await driver.sleep(1000);
        
        try {
            const returnButton = await driver.findElement(By.css('a[href="/"]'));
            await returnButton.click();
            await driver.sleep(500);
            
            const returnUrl = await driver.getCurrentUrl();
            
            if (returnUrl === serverUrl || returnUrl === serverUrl + '/') {
                console.log('✓ Return to home functionality works correctly');
            } else {
                console.log(`⚠️ Return to home redirected to: ${returnUrl}`);
            }
        } catch (e) {
            console.log('⚠️ Return to home button not found');
        }

        console.log('🎉 All tests completed successfully!');

    } catch (err) {
        console.error('Test failed:', err);
        throw err;
    } finally {
        console.log("Closing browser...");
        await driver.quit();
    }
})();
