const express = require('express');
const fs = require('fs');
const path = require('path'); 
const { body, validationResult } = require('express-validator');

// App Instance
const app = express();
app.use(express.urlencoded({ extended: true })); 
app.use(express.static('public'));

// Helper functions
function validateXSS(input) {
    if (!input || typeof input !== 'string') {
        return false;
    }

    // XSS patterns to detect
    const xssPatterns = [
        // Script tags
        /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
        /<script[\s\S]*?>/gi,
        
        // JavaScript events
        /on\w+\s*=\s*["'][^"']*["']/gi,
        /on\w+\s*=\s*[^>\s]+/gi,
        
        // JavaScript URLs
        /javascript\s*:/gi,
        /vbscript\s*:/gi,
        /data\s*:/gi,
        
        // HTML tags commonly used in XSS
        /<(iframe|object|embed|form|img|svg|math|details|marquee)/gi,
        
        // Style injections
        /<style[\s\S]*?>/gi,
        /style\s*=\s*["'][^"']*["']/gi,
        
        // Common XSS payloads
        /alert\s*\(/gi,
        /confirm\s*\(/gi,
        /prompt\s*\(/gi,
        /eval\s*\(/gi,
        /document\.(cookie|domain|location)/gi,
        /window\.(location|open)/gi,
        
        // Encoded attacks
        /&#x[0-9a-f]+;/gi,
        /&#[0-9]+;/gi,
        /%[0-9a-f]{2}/gi,
        
        // Expression and import
        /expression\s*\(/gi,
        /@import/gi,
        
        // Meta refresh
        /<meta[\s\S]*?refresh/gi
    ];

    // Check against all XSS patterns
    for (const pattern of xssPatterns) {
        if (pattern.test(input)) {
            return false; // XSS detected
        }
    }

    return true; // Input is safe
}
function validateSQLInjection(input) {
    if (!input || typeof input !== 'string') {
        return false;
    }

    // SQL injection patterns to detect
    const sqlPatterns = [
        // Basic SQL keywords
        /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|OR|AND)\b)/gi,
        
        // SQL comments
        /(--|\#|\/\*|\*\/)/g,
        
        // SQL operators and syntax
        /(\bOR\b\s+\b\d+\s*=\s*\d+)/gi,  // OR 1=1
        /(\bAND\b\s+\b\d+\s*=\s*\d+)/gi, // AND 1=1
        /(\bOR\b\s+['"]\w+['"]?\s*=\s*['"]\w+['"]?)/gi, // OR 'a'='a'
        
        // Common injection attempts
        /'\s*(OR|AND)\s*'/gi,
        /'\s*;\s*/g,                     // Single quote followed by semicolon
        /'\s*(UNION|SELECT)/gi,
        
        // Hex values often used in injection
        /0x[0-9a-f]+/gi,
        
        // Specific database functions
        /(\b(SLEEP|BENCHMARK|WAITFOR|DELAY)\b)/gi,
        
        // Information schema attacks
        /(information_schema|sysobjects|syscolumns)/gi,
        
        // Stacked queries
        /;\s*(SELECT|INSERT|UPDATE|DELETE|DROP)/gi,
        
        // Blind injection patterns
        /(\bLIKE\b\s*['"][%_])/gi,
        
        // Time-based patterns
        /(SLEEP\s*\(|WAITFOR\s+DELAY|BENCHMARK\s*\()/gi,
        
        // Error-based patterns
        /(EXTRACTVALUE|UPDATEXML|EXP|CAST)/gi,
        
        // Boolean-based patterns
        /(\bIF\b\s*\()/gi,
        
        // Multiple single quotes (common in injection)
        /'{2,}/g,
        
        // Parentheses with SQL keywords
        /\(\s*(SELECT|INSERT|UPDATE|DELETE)/gi
    ];

    // Check against all SQL injection patterns
    for (const pattern of sqlPatterns) {
        if (pattern.test(input)) {
            return false; // SQL injection detected
        }
    }

    return true; // Input is safe
}



// Routes ---
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'web', 'index.html'));
});


app.post('/search', (req, res) => {
    const term = req.body.term;
    if (!term) {
        return res.status(400).send('Empty search field');
    }

    // Allow only letters, numbers and spaces. up to 100 character long.
    const termPattern = /^[A-Za-z0-9 ]{1,100}$/;
    if (!termPattern.test(term)) {
        return res.redirect('/');
    }
    
    // Deny base on patterns
    if (!validateXSS(term)){
        return res.redirect('/');
    }
    if (!validateSQLInjection(term)){
        return res.redirect('/');
    }

    res.redirect(`/search?term=${encodeURIComponent(term)}`);

});

app.get('/search', (req, res) => {
  const term = req.query.term;
  if (!term) return res.redirect('/');
  res.send(`
    <!DOCTYPE html>
    <html>
      <body>
        <h1>Search Results</h1>
        <p>You searched for: <strong>${term}</strong></p>
        <a href="/"><button>Return to Homepage</button></a>
      </body>
    </html>
  `);
});


// Start Server
app.listen(3000, () => {
    console.log('Web server listening running on port 3000');
});

