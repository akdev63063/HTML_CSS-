/**
 * JWT Token Storage Utility
 * Provides functions to manage JWT tokens stored in localStorage
 */

const TokenManager = {
  // Get token from localStorage
  getToken() {
    return localStorage.getItem('token');
  },

  // Get username from localStorage
  getUsername() {
    return localStorage.getItem('username');
  },

  // Get role from localStorage
  getRole() {
    return localStorage.getItem('role');
  },

  // Check if user is logged in
  isLoggedIn() {
    return !!this.getToken();
  },

  // Get Authorization header object for fetch requests
  getAuthHeader() {
    const token = this.getToken();
    if (token) {
      return {
        'Authorization': `Bearer ${token}`
      };
    }
    return {};
  },

  // Make authenticated API request
  async fetchWithAuth(url, options = {}) {
    const headers = {
      ...options.headers,
      ...this.getAuthHeader()
    };
    
    return fetch(url, {
      ...options,
      headers
    });
  },

  // Clear token (logout)
  clearToken() {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    localStorage.removeItem('role');
  },

  // Set token (used after login)
  setToken(token, username, role) {
    localStorage.setItem('token', token);
    localStorage.setItem('username', username);
    localStorage.setItem('role', role);
  }
};
