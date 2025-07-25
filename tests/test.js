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
    it('should block XSS attacks', async () => {
      const xssAttacks = [
        '<script>alert("XSS")</script>',
        'javascript:alert("XSS")',
        '<img src=x onerror=alert("XSS")>',
        '<iframe src="javascript:alert(1)"></iframe>'
      ];

      for (const attack of xssAttacks) {
        const response = await request(app)
          .post('/search')
          .send({ searchTerm: attack })
          .expect(200);
        
        expect(response.text).to.include('Invalid input detected');
        expect(response.text).to.include('<form action="/search" method="POST">');
        expect(response.text).to.include('value=""');
      }
    });
  });

  describe('SQL Injection Prevention', () => {
    it('should block SQL injection attacks', async () => {
      const sqlAttacks = [
        "' UNION SELECT * FROM users --",
        "admin' OR 1=1 --",
        "'; DROP TABLE users; --",
        "SELECT password FROM users"
      ];

      for (const attack of sqlAttacks) {
        const response = await request(app)
          .post('/search')
          .send({ searchTerm: attack })
          .expect(200);
        
        expect(response.text).to.include('Invalid input detected');
        expect(response.text).to.include('<form action="/search" method="POST">');
      }
    });
  });

  describe('Input Validation Edge Cases', () => {
    it('should handle invalid inputs', async () => {
      const invalidInputs = [
        { searchTerm: '' },
        { searchTerm: null },
        {}
      ];

      for (const input of invalidInputs) {
        const response = await request(app)
          .post('/search')
          .send(input)
          .expect(200);
        
        expect(response.text).to.include('Invalid input detected');
        expect(response.text).to.include('<form action="/search" method="POST">');
      }
    });
  });

  describe('Security Compliance', () => {
    it('should validate inputs according to OWASP guidelines', async () => {
      const attackVectors = [
        '<script>alert("XSS")</script>',
        'javascript:alert("XSS")',
        "' OR '1'='1",
        "1; DROP TABLE users; --"
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
      
      expect(response.text).to.include('value=""');
      expect(response.text).not.to.include('value="<script>');
    });
  });

  describe('Functional Requirements', () => {
    it('should meet all basic requirements', async () => {
      // Test home page
      const homeResponse = await request(app).get('/');
      expect(homeResponse.text).to.include('<form');
      expect(homeResponse.text).to.include('name="searchTerm"');
      expect(homeResponse.text).to.include('type="submit"');

      // Test valid input goes to results page
      const validResponse = await request(app)
        .post('/search')
        .send({ searchTerm: 'valid search' });
      
      expect(validResponse.text).to.include('Search Results');
      expect(validResponse.text).to.include('Search Term: valid search');
      expect(validResponse.text).to.include('Return to Home Page');

      // Test XSS blocked and stays on home page
      const xssResponse = await request(app)
        .post('/search')
        .send({ searchTerm: '<script>alert("test")</script>' });
      
      expect(xssResponse.text).to.include('<form action="/search" method="POST">');
      expect(xssResponse.text).to.include('value=""');
      expect(xssResponse.text).not.to.include('Search Results');
    });
  });
});
