import { expect } from 'chai';
import request from 'supertest';
import app from '../src/server.js';

describe('Secure Search Application', () => {
  
  describe('Home Page', () => {
    it('should return the home page with search form', async () => {
      const response = await request(app)
        .get('/')
        .expect(200);
      
      expect(response.text).to.include('<form action="/search" method="POST">');
      expect(response.text).to.include('<input type="text" name="searchTerm"');
      expect(response.text).to.include('<button type="submit">Search</button>');
    });
  });

  describe('Valid Input Handling', () => {
    it('should accept valid search terms and display results', async () => {
      const response = await request(app)
        .post('/search')
        .send({ searchTerm: 'hello world' })
        .expect(200);
      
      expect(response.text).to.include('Search Results');
      expect(response.text).to.include('Search Term: hello world');
      expect(response.text).to.include('<a href="/">Return to Home Page</a>');
    });

    it('should accept alphanumeric search terms', async () => {
      const response = await request(app)
        .post('/search')
        .send({ searchTerm: 'test123' })
        .expect(200);
      
      expect(response.text).to.include('Search Results');
      expect(response.text).to.include('Search Term: test123');
    });
  });

  describe('XSS Attack Prevention', () => {
    it('should block script tag XSS attacks', async () => {
      const response = await request(app)
        .post('/search')
        .send({ searchTerm: '<script>alert("XSS")</script>' })
        .expect(200);
      
      expect(response.text).to.include('Invalid input detected');
      expect(response.text).to.include('<form action="/search" method="POST">');
      expect(response.text).to.include('value=""'); // Input should be cleared
    });

    it('should block javascript: URL XSS attacks', async () => {
      const response = await request(app)
        .post('/search')
        .send({ searchTerm: 'javascript:alert("XSS")' })
        .expect(200);
      
      expect(response.text).to.include('Invalid input detected');
      expect(response.text).to.include('<form action="/search" method="POST">');
    });

    it('should block event handler XSS attacks', async () => {
      const response = await request(app)
        .post('/search')
        .send({ searchTerm: '<img src=x onerror=alert("XSS")>' })
        .expect(200);
      
      expect(response.text).to.include('Invalid input detected');
      expect(response.text).to.include('<form action="/search" method="POST">');
    });

    it('should block iframe XSS attacks', async () => {
      const response = await request(app)
        .post('/search')
        .send({ searchTerm: '<iframe src="javascript:alert(1)"></iframe>' })
        .expect(200);
      
      expect(response.text).to.include('Invalid input detected');
      expect(response.text).to.include('<form action="/search" method="POST">');
    });
  });

  describe('SQL Injection Prevention', () => {
    it('should block UNION SELECT attacks', async () => {
      const response = await request(app)
        .post('/search')
        .send({ searchTerm: "' UNION SELECT * FROM users --" })
        .expect(200);
      
      expect(response.text).to.include('Invalid input detected');
      expect(response.text).to.include('<form action="/search" method="POST">');
      expect(response.text).to.include('value=""'); // Input should be cleared
    });

    it('should block OR 1=1 attacks', async () => {
      const response = await request(app)
        .post('/search')
        .send({ searchTerm: "admin' OR 1=1 --" })
        .expect(200);
      
      expect(response.text).to.include('Invalid input detected');
      expect(response.text).to.include('<form action="/search" method="POST">');
    });

    it('should block DROP TABLE attacks', async () => {
      const response = await request(app)
        .post('/search')
        .send({ searchTerm: "'; DROP TABLE users; --" })
        .expect(200);
      
      expect(response.text).to.include('Invalid input detected');
      expect(response.text).to.include('<form action="/search" method="POST">');
    });

    it('should block SELECT statement attacks', async () => {
      const response = await request(app)
        .post('/search')
        .send({ searchTerm: "SELECT password FROM users" })
        .expect(200);
      
      expect(response.text).to.include('Invalid input detected');
      expect(response.text).to.include('<form action="/search" method="POST">');
    });
  });

  describe('Input Validation Edge Cases', () => {
    it('should handle empty input', async () => {
      const response = await request(app)
        .post('/search')
        .send({ searchTerm: '' })
        .expect(200);
      
      expect(response.text).to.include('Invalid input detected');
      expect(response.text).to.include('<form action="/search" method="POST">');
    });

    it('should handle null input', async () => {
      const response = await request(app)
        .post('/search')
        .send({ searchTerm: null })
        .expect(200);
      
      expect(response.text).to.include('Invalid input detected');
      expect(response.text).to.include('<form action="/search" method="POST">');
    });

    it('should handle undefined input', async () => {
      const response = await request(app)
        .post('/search')
        .send({})
        .expect(200);
      
      expect(response.text).to.include('Invalid input detected');
      expect(response.text).to.include('<form action="/search" method="POST">');
    });
  });

  describe('OWASP Top 10 Proactive Control C5 Compliance', () => {
    it('should validate all inputs according to OWASP guidelines', async () => {
      // Test multiple attack vectors in sequence
      const attackVectors = [
        '<script>alert("XSS")</script>',
        'javascript:alert("XSS")',
        "' OR '1'='1",
        "1; DROP TABLE users; --",
        '<iframe src="data:text/html,<script>alert(1)</script>"></iframe>'
      ];

      for (const attack of attackVectors) {
        const response = await request(app)
          .post('/search')
          .send({ searchTerm: attack });
        
        expect(response.status).to.equal(200);
        expect(response.text).to.include('Invalid input detected');
        expect(response.text).to.include('<form action="/search" method="POST">');
      }
    });

    it('should clear input field when attack is detected', async () => {
      const response = await request(app)
        .post('/search')
        .send({ searchTerm: '<script>alert("test")</script>' })
        .expect(200);
      
      // Check that the input field is cleared (value="")
      expect(response.text).to.include('value=""');
      expect(response.text).not.to.include('value="<script>');
    });

    it('should remain on home page after attack detection', async () => {
      const response = await request(app)
        .post('/search')
        .send({ searchTerm: "' UNION SELECT password FROM users --" })
        .expect(200);
      
      // Should show the form again, not redirect to results page
      expect(response.text).to.include('<form action="/search" method="POST">');
      expect(response.text).to.include('Invalid input detected');
      expect(response.text).not.to.include('Search Results');
    });
  });

  describe('Functional Requirements Compliance', () => {
    it('should meet requirement (a): home page with form and input field', async () => {
      const response = await request(app).get('/');
      
      expect(response.text).to.include('<form');
      expect(response.text).to.include('name="searchTerm"');
      expect(response.text).to.include('type="submit"');
    });

    it('should meet requirement (c): clear input and remain on home page for XSS', async () => {
      const response = await request(app)
        .post('/search')
        .send({ searchTerm: '<script>alert("test")</script>' });
      
      expect(response.text).to.include('<form action="/search" method="POST">');
      expect(response.text).to.include('value=""');
    });

    it('should meet requirement (d): go to new page for valid input', async () => {
      const response = await request(app)
        .post('/search')
        .send({ searchTerm: 'valid search' });
      
      expect(response.text).to.include('Search Results');
      expect(response.text).to.include('Search Term: valid search');
      expect(response.text).to.include('Return to Home Page');
    });

    it('should meet requirement (e): go to new page for non-SQL injection input', async () => {
      const response = await request(app)
        .post('/search')
        .send({ searchTerm: 'normal search query' });
      
      expect(response.text).to.include('Search Results');
      expect(response.text).to.include('Return to Home Page');
    });
  });
});
