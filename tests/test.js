const { expect } = require('chai');
const request = require('supertest');
const app = require('../src/server.js');

describe('Secure Search Application', () => {
  
  describe('Home Page', () => {
    it('should return home page with search form', async () => {
      const response = await request(app)
        .get('/')
        .expect(200);
      
      expect(response.text).to.include('<h1>Search Application</h1>');
      expect(response.text).to.include('<form action="/search" method="POST">');
      expect(response.text).to.include('name="searchTerm"');
      expect(response.text).to.include('<button type="submit">Search</button>');
    });
  });

  describe('XSS Attack Prevention', () => {
    it('should block script tag attacks', async () => {
      const response = await request(app)
        .post('/search')
        .send({ searchTerm: '<script>alert("XSS")</script>' })
        .expect(200);
      
      expect(response.text).to.include('Invalid input detected');
      expect(response.text).to.include('<form action="/search" method="POST">');
      expect(response.text).to.include('value=""');
    });

    it('should block javascript URL attacks', async () => {
      const response = await request(app)
        .post('/search')
        .send({ searchTerm: 'javascript:alert("XSS")' })
        .expect(200);
      
      expect(response.text).to.include('Invalid input detected');
      expect(response.text).to.include('<form action="/search" method="POST">');
    });

    it('should block event handler attacks', async () => {
      const response = await request(app)
        .post('/search')
        .send({ searchTerm: '<img src=x onerror=alert("XSS")>' })
        .expect(200);
      
      expect(response.text).to.include('Invalid input detected');
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
    });

    it('should block OR 1=1 attacks', async () => {
      const response = await request(app)
        .post('/search')
        .send({ searchTerm: "admin' OR 1=1 --" })
        .expect(200);
      
      expect(response.text).to.include('Invalid input detected');
    });

    it('should block DROP TABLE attacks', async () => {
      const response = await request(app)
        .post('/search')
        .send({ searchTerm: "'; DROP TABLE users; --" })
        .expect(200);
      
      expect(response.text).to.include('Invalid input detected');
    });
  });

  describe('Input Validation', () => {
    it('should reject empty input', async () => {
      const response = await request(app)
        .post('/search')
        .send({ searchTerm: '' })
        .expect(200);
      
      expect(response.text).to.include('Invalid input detected');
    });

    it('should reject null input', async () => {
      const response = await request(app)
        .post('/search')
        .send({ searchTerm: null })
        .expect(200);
      
      expect(response.text).to.include('Invalid input detected');
    });

    it('should reject undefined input', async () => {
      const response = await request(app)
        .post('/search')
        .send({})
        .expect(200);
      
      expect(response.text).to.include('Invalid input detected');
    });
  });

  describe('Security Requirements', () => {
    it('should clear input field when attack is detected', async () => {
      const response = await request(app)
        .post('/search')
        .send({ searchTerm: '<script>alert("test")</script>' })
        .expect(200);
      
      expect(response.text).to.include('value=""');
      expect(response.text).not.to.include('value="<script>');
    });

    it('should stay on home page after detecting attack', async () => {
      const response = await request(app)
        .post('/search')
        .send({ searchTerm: "' OR 1=1 --" })
        .expect(200);
      
      expect(response.text).to.include('<form action="/search" method="POST">');
      expect(response.text).to.include('Invalid input detected');
      expect(response.text).not.to.include('Search Results');
    });
  });
});