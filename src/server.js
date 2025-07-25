const express = require('express');
const app = express();
const PORT = 80;

// Middleware for parsing form data
app.use(express.urlencoded({ extended: true }));

/**
 * Input validation function based on OWASP Top 10 Proactive Control C5
 * Validates against XSS and SQL injection attacks
 * @param {string} input - The user input to validate
 * @returns {object} - Validation result with isValid boolean and attackType
 */
function validateInput(input) {
    if (!input || typeof input !== 'string') {
        return { isValid: false, attackType: 'invalid' };
    }

    // Check for XSS patterns
    const xssPatterns = [
        /<script/gi,
        /javascript:/gi,
        /on\w+\s*=/gi,
        /<iframe/gi,
        /<object/gi,
        /<embed/gi,
        /alert\s*\(/gi,
        /eval\s*\(/gi,
        /document\./gi,
        /window\./gi
    ];

    // Check for SQL injection patterns
    const sqlPatterns = [
        /(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|UNION|DECLARE)/gi,
        /('|;|--|\/\*|\*\/)/gi,
        /(OR|AND)\s+['"]*\d+['"]*\s*=\s*['"]*\d+['"]*\s*(--)?/gi,
        /1\s*=\s*1/gi,
        /'.*OR.*'/gi,
        /".*OR.*"/gi
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

// Start the server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});

module.exports = app;
