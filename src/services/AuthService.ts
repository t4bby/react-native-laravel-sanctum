import TokenStorage from '../utils/TokenStorage';
import type { AuthConfig, User } from 'react-native-laravel-sanctum';
import axios from 'axios';

class AuthService {
  private readonly config: AuthConfig | null;
  private csrfToken: string | null = null; // CSRF-Token speichern

  constructor(authConfig: AuthConfig) {
    if (authConfig === null) {
      throw new Error('AuthConfig is null');
    }
    this.config = authConfig;
  }

  private async fetchCSRFToken() {
    try {
      if (!this.config || !this.config.csrfTokenUrl) {
        return;
      }

      const response = await axios.get(this.config.csrfTokenUrl, {
        headers: {
          'Content-Type': 'application/json',
        },
      });

      // Extrahieren des CSRF-Tokens aus dem Set-Cookie-Header
      const setCookieHeader = response.headers['Set-Cookie'];
      if (setCookieHeader) {
        const csrfTokenMatch = setCookieHeader.match(/XSRF-TOKEN=([^;]*)/);
        if (csrfTokenMatch) {
          this.csrfToken = csrfTokenMatch[1] ?? null;
        }
      }
    } catch (error) {
      console.error('Error while fetching CSRF token:', error);
      throw error;
    }
  }

  private async getRequestHeaders() {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (this.csrfToken) {
      headers['X-XSRF-TOKEN'] = this.csrfToken;
    }

    const currentToken = await TokenStorage.getToken();
    if (currentToken) {
      headers.Authorization = `Bearer ${currentToken}`;
    }

    return headers;
  }

  async login(
    email: string,
    password: string,
    deviceName: string
  ): Promise<boolean> {
    try {
      if (!this.config) {
        throw new Error('Authentication configuration is missing');
      }

      if (this.config.csrfTokenUrl) {
        await this.fetchCSRFToken();
      }

      const response = await axios.post(this.config.loginUrl, {
        email: email,
        password: password,
        device_name: deviceName,
      });

      const token = response.data.token;

      if (token) {
        await TokenStorage.saveToken(JSON.stringify(token).replace(/"/g, ''));
        return true;
      } else {
        return false;
      }
    } catch (error) {
      console.error('Error during login:', error);
      throw error;
    }
  }

  async logout(): Promise<boolean> {
    try {
      if (!this.config) {
        throw new Error('Authentication configuration is missing');
      }

      if (this.config.csrfTokenUrl) {
        await this.fetchCSRFToken();
      }

      const currentToken = await TokenStorage.getToken();

      if (currentToken === null) {
        return true;
      }

      await axios.post(
        this.config.logoutUrl,
        {},
        {
          headers: await this.getRequestHeaders(),
        }
      );

      await TokenStorage.removeToken();
      return true;
    } catch (error) {
      console.error('Error during logout:', error);
      throw error;
    }
  }

  async getUser(): Promise<User | null> {
    try {
      if (!this.config) {
        throw new Error('Authentication configuration is missing');
      }

      const currentToken = await TokenStorage.getToken();

      if (currentToken === null) {
        return null;
      }

      if (this.config.csrfTokenUrl) {
        await this.fetchCSRFToken();
      }

      const response = await axios.get(this.config.userUrl, {
        headers: await this.getRequestHeaders(),
      });

      const user = response.data;

      if (user) {
        this.csrfToken = null;
        return user;
      } else {
        return null;
      }
    } catch (error) {
      console.error('Error while fetching user:', error);
      throw error;
    }
  }
}

export default AuthService;
