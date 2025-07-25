const express = require('express');
const helmet = require('helmet');
const validator = require('validator');
const { JSDOM } = require('jsdom');
const DOMPurify = require('dompurify');

const app = express();
const PORT = 80;

// Initialize DOMPurify with JSDOM
const window = new JSDOM('').window;
const purify = DOMPurify(window);

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"]
        }
    }
}));

// Middleware for parsing form data
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

/**
 * Comprehensive input validation function based on OWASP Top 10 Proactive Control C5
 * Validates against XSS and SQL injection attacks
 * @param {string} input - The user input to validate
 * @returns {object} - Validation result with isValid boolean and reason
 */
function validateInput(input) {
    if (!input || typeof input !== 'string') {
        return { isValid: false, reason: 'Invalid input type' };
    }

    // Check for common XSS patterns
    const xssPatterns = [
        /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
        /javascript:/gi,
        /on\w+\s*=/gi,
        /<iframe/gi,
        /<object/gi,
        /<embed/gi,
        /<link/gi,
        /<meta/gi,
        /<style/gi,
        /vbscript:/gi,
        /data:text\/html/gi,
        /expression\s*\(/gi,
        /<img[^>]+src[^>]*=/gi,
        /alert\s*\(/gi,
        /confirm\s*\(/gi,
        /prompt\s*\(/gi,
        /document\./gi,
        /window\./gi,
        /eval\s*\(/gi,
        /setTimeout\s*\(/gi,
        /setInterval\s*\(/gi
    ];

    // Check for SQL injection patterns
    const sqlInjectionPatterns = [
        /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|DECLARE)\b)/gi,
        /('|(\\)|;|--|\/\*|\*\/)/gi,
        /(OR|AND)\s+['"]*\d+['"]*\s*=\s*['"]*\d+['"]*\s*(--)?/gi,
        /\s+(OR|AND)\s+['"]*[a-zA-Z]+['"]*\s*=\s*['"]*[a-zA-Z]+['"]*\s*(--)?/gi,
        /1\s*=\s*1/gi,
        /'.*OR.*'/gi,
        /".*OR.*"/gi,
        /\bUNION\s+(ALL\s+)?SELECT\b/gi,
        /\bINSERT\s+INTO\b/gi,
        /\bDROP\s+TABLE\b/gi,
        /\bTRUNCATE\s+TABLE\b/gi,
        /\bEXEC\s*\(/gi,
        /\bxp_cmdshell\b/gi,
        /\bsp_executesql\b/gi
    ];

    // Test for XSS patterns
    for (let pattern of xssPatterns) {
        if (pattern.test(input)) {
            return { isValid: false, reason: 'XSS Attack detected' };
        }
    }

    // Test for SQL injection patterns
    for (let pattern of sqlInjectionPatterns) {
        if (pattern.test(input)) {
            return { isValid: false, reason: 'SQL Injection attack detected' };
        }
    }

    // Additional validation using DOMPurify
    const sanitized = purify.sanitize(input);
    if (sanitized !== input) {
        return { isValid: false, reason: 'XSS Attack detected by DOMPurify' };
    }

    // Check for excessive length (potential buffer overflow)
    if (input.length > 1000) {
        return { isValid: false, reason: 'Input too long' };
    }

    // Check for null bytes
    if (input.includes('\0')) {
        return { isValid: false, reason: 'Null byte detected' };
    }

    // Validate that input contains only safe characters (alphanumeric, spaces, and basic punctuation)
    if (!/^[a-zA-Z0-9\s\.,!?'"()-]+$/.test(input)) {
        return { isValid: false, reason: 'Invalid characters detected' };
    }

    return { isValid: true, reason: 'Input is safe' };
}

// Home page route
app.get('/', (req, res) => {
    const homePageHTML = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Secure Search Application</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 800px;
                margin: 50px auto;
                padding: 20px;
                background-color: #f5f5f5;
            }
            .container {
                background-color: white;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            h1 {
                color: #333;
                text-align: center;
                margin-bottom: 30px;
            }
            .form-group {
                margin-bottom: 20px;
            }
            label {
                display: block;
                margin-bottom: 5px;
                font-weight: bold;
                color: #555;
            }
            input[type="text"] {
                width: 100%;
                padding: 12px;
                border: 2px solid #ddd;
                border-radius: 4px;
                font-size: 16px;
                box-sizing: border-box;
            }
            input[type="text"]:focus {
                border-color: #4CAF50;
                outline: none;
            }
            button {
                background-color: #4CAF50;
                color: white;
                padding: 12px 24px;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                font-size: 16px;
                width: 100%;
            }
            button:hover {
                background-color: #45a049;
            }
            .error {
                color: #d32f2f;
                margin-top: 10px;
                padding: 10px;
                background-color: #ffebee;
                border-radius: 4px;
                border-left: 4px solid #d32f2f;
            }
            .security-note {
                background-color: #e3f2fd;
                padding: 15px;
                border-radius: 4px;
                border-left: 4px solid #2196F3;
                margin-top: 20px;
                font-size: 14px;
                color: #1976d2;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔍 Secure Search Application</h1>
            <form action="/search" method="POST">
                <div class="form-group">
                    <label for="searchTerm">Enter Search Term:</label>
                    <input type="text" id="searchTerm" name="searchTerm" required 
                           placeholder="Enter your search term here..." maxlength="1000">
                </div>
                <button type="submit">🔍 Search</button>
            </form>
            
            <div class="security-note">
                <strong>🛡️ Security Notice:</strong> This application implements OWASP Top 10 Proactive Control C5 
                to validate all inputs and prevent XSS and SQL injection attacks.
            </div>
        </div>
    </body>
    </html>
    `;
    
    res.send(homePageHTML);
});

// Search route with input validation
app.post('/search', (req, res) => {
    const { searchTerm } = req.body;
    
    // Validate the input
    const validation = validateInput(searchTerm);
    
    if (!validation.isValid) {
        // If validation fails, return to home page with error
        const errorPageHTML = `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Secure Search Application - Security Alert</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    max-width: 800px;
                    margin: 50px auto;
                    padding: 20px;
                    background-color: #f5f5f5;
                }
                .container {
                    background-color: white;
                    padding: 30px;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }
                h1 {
                    color: #d32f2f;
                    text-align: center;
                    margin-bottom: 30px;
                }
                .error {
                    color: #d32f2f;
                    margin: 20px 0;
                    padding: 15px;
                    background-color: #ffebee;
                    border-radius: 4px;
                    border-left: 4px solid #d32f2f;
                    font-weight: bold;
                }
                .form-group {
                    margin-bottom: 20px;
                }
                label {
                    display: block;
                    margin-bottom: 5px;
                    font-weight: bold;
                    color: #555;
                }
                input[type="text"] {
                    width: 100%;
                    padding: 12px;
                    border: 2px solid #ddd;
                    border-radius: 4px;
                    font-size: 16px;
                    box-sizing: border-box;
                }
                input[type="text"]:focus {
                    border-color: #4CAF50;
                    outline: none;
                }
                button {
                    background-color: #4CAF50;
                    color: white;
                    padding: 12px 24px;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                    font-size: 16px;
                    width: 100%;
                }
                button:hover {
                    background-color: #45a049;
                }
                .warning {
                    background-color: #fff3cd;
                    padding: 15px;
                    border-radius: 4px;
                    border-left: 4px solid #ffc107;
                    margin-top: 20px;
                    color: #856404;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🚨 Security Alert</h1>
                <div class="error">
                    <strong>Security Violation Detected:</strong> ${validation.reason}
                </div>
                
                <div class="warning">
                    <strong>⚠️ Warning:</strong> Your input has been cleared for security reasons. 
                    Please enter a valid search term without potentially malicious content.
                </div>
                
                <form action="/search" method="POST">
                    <div class="form-group">
                        <label for="searchTerm">Enter Search Term:</label>
                        <input type="text" id="searchTerm" name="searchTerm" required 
                               placeholder="Enter a safe search term..." maxlength="1000" value="">
                    </div>
                    <button type="submit">🔍 Search Again</button>
                </form>
                
                <div style="text-align: center; margin-top: 20px;">
                    <a href="/" style="color: #2196F3; text-decoration: none;">← Return to Home Page</a>
                </div>
            </div>
        </body>
        </html>
        `;
        
        res.send(errorPageHTML);
        return;
    }
    
    // If validation passes, show search results
    const resultsPageHTML = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Search Results - Secure Search Application</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 800px;
                margin: 50px auto;
                padding: 20px;
                background-color: #f5f5f5;
            }
            .container {
                background-color: white;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            h1 {
                color: #4CAF50;
                text-align: center;
                margin-bottom: 30px;
            }
            .search-result {
                background-color: #f8f9fa;
                padding: 20px;
                border-radius: 4px;
                border-left: 4px solid #4CAF50;
                margin: 20px 0;
            }
            .search-term {
                font-size: 18px;
                font-weight: bold;
                color: #333;
                word-wrap: break-word;
            }
            button {
                background-color: #2196F3;
                color: white;
                padding: 12px 24px;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                font-size: 16px;
                text-decoration: none;
                display: inline-block;
                margin-top: 20px;
            }
            button:hover {
                background-color: #1976D2;
            }
            .success {
                background-color: #e8f5e8;
                padding: 15px;
                border-radius: 4px;
                border-left: 4px solid #4CAF50;
                margin-top: 20px;
                color: #2e7d32;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>✅ Search Results</h1>
            <div class="search-result">
                <strong>Search Term:</strong>
                <div class="search-term">"${validator.escape(searchTerm)}"</div>
            </div>
            
            <div class="success">
                <strong>✅ Security Check Passed:</strong> Your input has been validated and deemed safe. 
                No XSS or SQL injection patterns were detected.
            </div>
            
            <div style="text-align: center; margin-top: 30px;">
                <a href="/" style="background-color: #2196F3; color: white; padding: 12px 24px; 
                   border: none; border-radius: 4px; text-decoration: none; display: inline-block;">
                    🏠 Return to Home Page
                </a>
            </div>
        </div>
    </body>
    </html>
    `;
    
    res.send(resultsPageHTML);
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Error:', err.message);
    res.status(500).send(`
        <html>
        <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
            <h1 style="color: #d32f2f;">Server Error</h1>
            <p>An unexpected error occurred. Please try again.</p>
            <a href="/" style="color: #2196F3;">Return to Home Page</a>
        </body>
        </html>
    `);
});

// 404 handler
app.use((req, res) => {
    res.status(404).send(`
        <html>
        <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
            <h1 style="color: #d32f2f;">Page Not Found</h1>
            <p>The page you're looking for doesn't exist.</p>
            <a href="/" style="color: #2196F3;">Return to Home Page</a>
        </body>
        </html>
    `);
});

// Start the server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Secure Search Application running on port ${PORT}`);
    console.log(`🛡️ Security features enabled: XSS protection, SQL injection prevention`);
    console.log(`📝 OWASP Top 10 Proactive Control C5 implemented`);
});

module.exports = app;
