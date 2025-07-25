import express from 'express';
const app = express();
const PORT = 80;

// Security: Disable Express version disclosure
app.disable('x-powered-by');

// Middleware for parsing form data
app.use(express.urlencoded({ extended: true }));

/**
 * Input validation function based on OWASP Top 10 Proactive Control C5
 * Validates against XSS and SQL injection attacks
 * @param {string} input - The user input to validate
 * @returns {object} - Validation result with isValid boolean and attackType
 */
function validateInput(input) {
    // More careful input validation
    if (input === null || input === undefined) {
        return { isValid: false, attackType: 'invalid' };
    }
    
    if (typeof input !== 'string') {
        return { isValid: false, attackType: 'invalid' };
    }
    
    if (input.trim() === '') {
        return { isValid: false, attackType: 'invalid' };
    }

    // Check for XSS patterns
    const xssPatterns = [
        /<script/gi,
        /javascript:/gi,
        /onclick=/gi,
        /onload=/gi,
        /onerror=/gi,
        /<iframe/gi,
        /<object/gi,
        /<embed/gi,
        /alert\(/gi,
        /eval\(/gi,
        /document\./gi,
        /window\./gi
    ];

    // Check for SQL injection patterns - simplified and more precise
    const sqlPatterns = [
        /\bUNION\s+SELECT\b/gi,
        /\bDROP\s+TABLE\b/gi,
        /'\s*OR\s+'\d+'\s*=\s*'\d+'/gi,
        /'\s*OR\s+\d+\s*=\s*\d+/gi,
        /admin'\s*OR\s*\d+\s*=\s*\d+/gi,
        /--\s*$/gi,
        /;\s*(DROP|DELETE|UPDATE|INSERT)\b/gi
    ];

    // Test for XSS patterns
    for (let pattern of xssPatterns) {
        if (pattern.test(input)) {
            return { isValid: false, attackType: 'xss' };
        }
    }

    // Test for SQL injection patterns
    for (let pattern of sqlPatterns) {
        if (pattern.test(input)) {
            return { isValid: false, attackType: 'sql' };
        }
    }

    return { isValid: true, attackType: null };
}

// Home page route
app.get('/', (req, res) => {
    res.send(`
        <html>
        <body>
            <h1>Search Application</h1>
            <form action="/search" method="POST">
                <input type="text" name="searchTerm" placeholder="Enter search term" required>
                <button type="submit">Search</button>
            </form>
        </body>
        </html>
    `);
});

// Search route with input validation
app.post('/search', (req, res) => {
    const { searchTerm } = req.body;
    
    // Validate the input
    const validation = validateInput(searchTerm);
    
    if (!validation.isValid) {
        // If validation fails (XSS or SQL injection), clear input and return to home page
        res.send(`
            <html>
            <body>
                <h1>Search Application</h1>
                <p>Invalid input detected. Please try again.</p>
                <form action="/search" method="POST">
                    <input type="text" name="searchTerm" placeholder="Enter search term" required value="">
                    <button type="submit">Search</button>
                </form>
            </body>
            </html>
        `);
        return;
    }
    
    // If validation passes, show search results
    res.send(`
        <html>
        <body>
            <h1>Search Results</h1>
            <p>Search Term: ${searchTerm}</p>
            <a href="/">Return to Home Page</a>
        </body>
        </html>
    `);
});

// Start the server only if this file is run directly (not imported for testing)
if (import.meta.url === `file://${process.argv[1]}`) {
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`Server running on port ${PORT}`);
    });
}

export default app;
