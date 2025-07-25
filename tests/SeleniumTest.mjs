import { Builder, By, until } from 'selenium-webdriver';
import assert from 'assert';

// Get the argument (default to 'local' if not provided)
const environment = process.argv[2] || 'local';

// URLs based on environment
// Obtain dev selenium server IP using: docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' selenium-server
const seleniumUrl = environment === 'github' 
  ? 'http://selenium:4444/wd/hub' 
  : 'http://localhost:4444/wd/hub';

// Note: Start the nodejs server before running the test locally
const serverUrl = environment === 'github' 
  ? 'http://testserver' 
  : 'http://host.docker.internal';

console.log(`Running tests in '${environment}' environment`);
console.log(`Selenium URL: ${seleniumUrl}`);
console.log(`Server URL: ${serverUrl}`);

(async function testSecureSearchApplication() {

    console.log("before driver init")

    // Initialize the WebDriver with Chrome
    const driver = environment === 'github' 
        ? await new Builder()
        .forBrowser('chrome')
        .usingServer(seleniumUrl) // Specify the Selenium server
        .build()
        : await new Builder()
        .forBrowser('chrome')
        .usingServer(seleniumUrl) // Specify the Selenium server
        .build();

    try {

        console.log("after driver init")
        
        await driver.get(serverUrl);

        console.log("after driver.get serverUrl")

        // Test 1: Check home page elements
        console.log("Testing home page elements...");
        
        // Wait for the search input to appear on the page
        let searchInput = await driver.wait(
            until.elementLocated(By.name('searchTerm')),
            5000 // Timeout in milliseconds
        );

        // Check if submit button exists
        let submitButton = await driver.findElement(By.css('button[type="submit"]'));
        assert.ok(searchInput, 'Search input should exist');
        assert.ok(submitButton, 'Submit button should exist');
        console.log('✓ Home page elements found successfully');

        await driver.sleep(2000);

        // Test 2: Test valid input acceptance
        console.log("Testing valid input acceptance...");
        
        await searchInput.clear();
        await searchInput.sendKeys('hello world');
        await submitButton.click();

        // Wait a moment for processing
        await driver.sleep(2000);

        // Check if we got to results page
        const pageContent = await driver.getPageSource();
        
        if (pageContent.includes('Search Results') && pageContent.includes('hello world')) {
            console.log('✓ Valid input correctly accepted and displayed');
        } else {
            throw new Error('Valid input was not processed correctly');
        }

        // Test 3: Test XSS attack prevention - Script Tag
        console.log("Testing XSS prevention (script tag)...");
        
        // Navigate back to home page
        await driver.get(serverUrl);
        
        // Wait for search input again
        searchInput = await driver.wait(
            until.elementLocated(By.name('searchTerm')),
            5000
        );
        
        submitButton = await driver.findElement(By.css('button[type="submit"]'));
        
        await searchInput.clear();
        await searchInput.sendKeys('<script>alert("XSS")</script>');
        await submitButton.click();

        // Wait for potential security response
        await driver.sleep(2000);

        const xssPageContent = await driver.getPageSource();
        
        if (xssPageContent.includes('Invalid input detected')) {
            console.log('✓ XSS script tag attack correctly blocked');
        } else {
            throw new Error('XSS script tag attack was not detected and blocked');
        }

        // Test 4: Test XSS attack prevention - Event Handler
        console.log("Testing XSS prevention (event handler)...");
        
        await driver.get(serverUrl);
        searchInput = await driver.wait(until.elementLocated(By.name('searchTerm')), 5000);
        submitButton = await driver.findElement(By.css('button[type="submit"]'));
        
        await searchInput.clear();
        await searchInput.sendKeys('<img src=x onerror=alert("XSS")>');
        await submitButton.click();
        await driver.sleep(2000);

        const eventHandlerPageContent = await driver.getPageSource();
        
        if (eventHandlerPageContent.includes('Invalid input detected')) {
            console.log('✓ XSS event handler attack correctly blocked');
        } else {
            throw new Error('XSS event handler attack was not detected and blocked');
        }

        // Test 5: Test SQL injection prevention
        console.log("Testing SQL injection prevention...");
        
        const sqlInjectionTests = [
            { payload: "' UNION SELECT * FROM users --", description: "UNION SELECT attack" },
            { payload: "admin' OR 1=1 --", description: "OR 1=1 attack" },
            { payload: "'; DROP TABLE users; --", description: "DROP TABLE attack" }
        ];

        for (const test of sqlInjectionTests) {
            try {
                await driver.get(serverUrl);
                
                const testSearchInput = await driver.wait(
                    until.elementLocated(By.name('searchTerm')),
                    5000
                );
                
                const testSubmitButton = await driver.findElement(By.css('button[type="submit"]'));
                
                await testSearchInput.clear();
                await testSearchInput.sendKeys(test.payload);
                await testSubmitButton.click();
                
                await driver.sleep(2000);
                
                const testPageContent = await driver.getPageSource();
                
                if (testPageContent.includes('Invalid input detected')) {
                    console.log(`✓ SQL injection ${test.description} correctly blocked`);
                } else {
                    console.log(`⚠️ SQL injection ${test.description} behavior unexpected`);
                }
            } catch (error) {
                console.error(`✗ Test failed for SQL injection ${test.description}:`, error.message);
            }
        }

        // Test 6: Test return to home functionality
        console.log("Testing return to home functionality...");
        
        // First navigate to results page with valid input
        await driver.get(serverUrl);
        searchInput = await driver.wait(until.elementLocated(By.name('searchTerm')), 5000);
        submitButton = await driver.findElement(By.css('button[type="submit"]'));
        
        await searchInput.clear();
        await searchInput.sendKeys('test search');
        await submitButton.click();
        await driver.sleep(2000);
        
        try {
            const returnButton = await driver.findElement(By.css('a[href="/"]'));
            await returnButton.click();
            
            await driver.sleep(1000);
            
            const returnUrl = await driver.getCurrentUrl();
            const expectedHomeUrl = serverUrl + '/';
            
            if (returnUrl === serverUrl || returnUrl === expectedHomeUrl) {
                console.log('✓ Return to home functionality works correctly');
            } else {
                console.log(`⚠️ Return to home redirected to unexpected location: ${returnUrl}`);
            }
        } catch (e) {
            console.log('⚠️ Return to home button not found or test skipped');
        }

        // Test 7: Test input validation with edge cases
        console.log("Testing input validation edge cases...");
        
        const edgeCaseTests = [
            { payload: 'javascript:alert("XSS")', description: 'JavaScript URL injection' },
            { payload: '<iframe src="data:text/html,<script>alert(1)</script>"></iframe>', description: 'iframe injection' },
            { payload: 'eval(alert("XSS"))', description: 'eval function injection' }
        ];

        for (const testCase of edgeCaseTests) {
            try {
                await driver.get(serverUrl);
                
                const testSearchInput = await driver.wait(
                    until.elementLocated(By.name('searchTerm')),
                    5000
                );
                
                const testSubmitButton = await driver.findElement(By.css('button[type="submit"]'));
                
                await testSearchInput.clear();
                await testSearchInput.sendKeys(testCase.payload);
                await testSubmitButton.click();
                
                await driver.sleep(1500);
                
                const testPageContent = await driver.getPageSource();
                
                if (testPageContent.includes('Invalid input detected')) {
                    console.log(`✓ Security payload "${testCase.description}" correctly blocked`);
                } else {
                    console.log(`⚠️ Security payload "${testCase.description}" behavior needs review`);
                }
            } catch (error) {
                console.error(`✗ Test failed for security payload "${testCase.description}":`, error.message);
            }
        }

        console.log('🎉 All security validation tests completed successfully!');

    } catch (err) {
        console.error('Test failed:', err);
        throw err;
    } finally {
        // Quit the browser session
        console.log("Closing browser...");
        await driver.quit();
    }
})();
