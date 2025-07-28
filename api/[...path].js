// Dynamic API route handler for Vercel
// This will handle all /api/* routes and forward them to our Express app

const express = require('express');
const session = require('express-session');
const axios = require('axios');
const crypto = require('crypto');

const app = express();

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

app.use(express.json());

// OAuth configuration
const oauthProviders = {
  github: {
    authUrl: 'https://github.com/login/oauth/authorize',
    tokenUrl: 'https://github.com/login/oauth/access_token',
    apiUrl: 'https://api.github.com',
    scopes: 'repo,user,read:org',
    clientId: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    redirectUri: process.env.GITHUB_REDIRECT_URI
  },
  notion: {
    authUrl: 'https://api.notion.com/v1/oauth/authorize',
    tokenUrl: 'https://api.notion.com/v1/oauth/token',
    apiUrl: 'https://api.notion.com/v1',
    clientId: process.env.NOTION_CLIENT_ID,
    clientSecret: process.env.NOTION_CLIENT_SECRET,
    redirectUri: process.env.NOTION_REDIRECT_URI
  }
};

// State store for OAuth (in production, use Redis or database)
const stateStore = new Map();

// Clean expired states
setInterval(() => {
  const now = Date.now();
  for (const [state, data] of stateStore.entries()) {
    if (data.expires < now) {
      stateStore.delete(state);
    }
  }
}, 5 * 60 * 1000); // Clean every 5 minutes

// OAuth routes
app.get('/auth/:provider/login', (req, res) => {
  const { provider } = req.params;
  const { redirect } = req.query;
  const config = oauthProviders[provider];

  if (!config || !config.clientId) {
    return res.status(400).json({
      error: 'OAuth provider not configured',
      message: `${provider} OAuth is not properly configured`
    });
  }

  try {
    // Generate state for CSRF protection
    const state = crypto.randomBytes(32).toString('hex');
    stateStore.set(state, {
      provider,
      timestamp: Date.now(),
      expires: Date.now() + 600000, // 10 minutes
      redirect
    });

    const params = new URLSearchParams({
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      state: state
    });

    if (provider === 'github') {
      params.append('scope', config.scopes);
    } else if (provider === 'notion') {
      params.append('owner', 'user');
      params.append('response_type', 'code');
    }

    const authUrl = `${config.authUrl}?${params.toString()}`;
    res.redirect(authUrl);
  } catch (error) {
    console.error('OAuth login error:', error);
    res.status(500).json({
      error: 'Failed to initiate OAuth',
      message: error.message
    });
  }
});

app.get('/auth/:provider/callback', async (req, res) => {
  const { provider } = req.params;
  const { code, state, error: oauthError } = req.query;
  const config = oauthProviders[provider];

  if (oauthError) {
    console.error('OAuth provider error:', oauthError);
    return res.redirect(`/auth/error?error=${encodeURIComponent(oauthError)}`);
  }

  if (!code || !state) {
    return res.status(400).json({
      error: 'Missing required parameters',
      message: 'Authorization code and state are required'
    });
  }

  // Validate state
  const stateData = stateStore.get(state);
  if (!stateData || stateData.provider !== provider || stateData.expires < Date.now()) {
    return res.status(400).json({
      error: 'Invalid or expired state parameter'
    });
  }
  stateStore.delete(state);

  try {
    // Exchange code for token
    const tokenData = await exchangeCodeForToken(provider, code, config);
    
    // Get user info
    const userInfo = await getUserInfo(provider, tokenData.access_token, config);
    
    // Store in session
    req.session[`${provider}_auth`] = {
      accessToken: tokenData.access_token,
      refreshToken: tokenData.refresh_token,
      expiresAt: tokenData.expires_in ? Date.now() + (tokenData.expires_in * 1000) : null,
      userInfo
    };

    // Redirect to success page or original destination
    const redirectUrl = stateData.redirect || '/oauth-demo.html';
    res.redirect(`${redirectUrl}?auth=success&provider=${provider}`);
  } catch (error) {
    console.error('OAuth callback error:', error);
    res.redirect(`/oauth-demo.html?error=${encodeURIComponent(error.message)}`);
  }
});

app.get('/auth/:provider/status', async (req, res) => {
  const { provider } = req.params;
  const authData = req.session?.[`${provider}_auth`];
  
  if (!authData || !authData.accessToken) {
    return res.json({
      authenticated: false,
      provider
    });
  }

  // Check if token is expired
  if (authData.expiresAt && authData.expiresAt < Date.now()) {
    delete req.session[`${provider}_auth`];
    return res.json({
      authenticated: false,
      provider,
      reason: 'Token expired'
    });
  }

  res.json({
    authenticated: true,
    provider,
    user: authData.userInfo,
    expiresAt: authData.expiresAt
  });
});

app.post('/auth/:provider/logout', (req, res) => {
  const { provider } = req.params;
  
  if (req.session) {
    delete req.session[`${provider}_auth`];
  }
  
  res.json({
    success: true,
    message: `Logged out from ${provider}`
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    service: 'FlashFusion OAuth API',
    providers: Object.keys(oauthProviders).map(provider => ({
      provider,
      configured: !!(oauthProviders[provider].clientId && oauthProviders[provider].clientSecret)
    }))
  });
});

// Helper functions
async function exchangeCodeForToken(provider, code, config) {
  const params = {
    client_id: config.clientId,
    client_secret: config.clientSecret,
    code: code,
    redirect_uri: config.redirectUri
  };

  if (provider === 'github') {
    params.grant_type = 'authorization_code';
  }

  const response = await axios.post(config.tokenUrl, params, {
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    },
    auth: provider === 'notion' ? {
      username: config.clientId,
      password: config.clientSecret
    } : undefined
  });

  return response.data;
}

async function getUserInfo(provider, accessToken, config) {
  if (provider === 'github') {
    const response = await axios.get(`${config.apiUrl}/user`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/json'
      }
    });
    
    return {
      id: response.data.id,
      login: response.data.login,
      name: response.data.name,
      email: response.data.email,
      avatar_url: response.data.avatar_url,
      html_url: response.data.html_url
    };
  } else if (provider === 'notion') {
    const response = await axios.get(`${config.apiUrl}/users/me`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Notion-Version': '2022-06-28'
      }
    });
    
    return {
      id: response.data.id,
      name: response.data.name,
      avatar_url: response.data.avatar_url,
      type: response.data.type,
      workspace_name: response.data.bot?.workspace_name
    };
  }
}

// Export for Vercel
module.exports = app;