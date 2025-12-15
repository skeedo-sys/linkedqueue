
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const dotenv = require('dotenv');
const session = require('express-session');

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

/**
 * CONFIGURATION
 */
const CLIENT_ID = process.env.LINKEDIN_CLIENT_ID || '863d3uk47dm5qp';
const CLIENT_SECRET = process.env.LINKEDIN_CLIENT_SECRET || 'WPL_AP1.kIOeZD88wBf2lXnF.+vIDZg==';
const REDIRECT_URI = process.env.REDIRECT_URI || 'http://localhost:3000/auth/linkedin/callback';

app.use(express.json());
app.set('trust proxy', 1);

const allowedOrigins = [
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'http://localhost:5173',
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin) || origin.includes('localhost') || origin.includes('127.0.0.1')) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

const sessionStore = new session.MemoryStore();

app.use(session({
  name: 'linkgrow.sid',
  secret: process.env.SESSION_SECRET || 'linkgrow-production-secure-key-2025-v2',
  resave: true,
  saveUninitialized: false, // Don't create session until something is stored
  rolling: true,
  store: sessionStore,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    path: '/'
  }
}));

/* -----------------------------------------------------------------
   IN-MEMORY SCHEDULED POST STORE & SCHEDULER
   ----------------------------------------------------------------- */
let scheduledPosts = [];

/**
 * Helper to publish a post directly via LinkedIn UGC API
 */
async function publishLinkedInPost(userUrn, accessToken, content) {
  console.log(`[LinkedIn] 🚀 Attempting to publish for ${userUrn}`);
  return axios.post('https://api.linkedin.com/v2/ugcPosts', {
    author: userUrn,
    lifecycleState: 'PUBLISHED',
    specificContent: {
      'com.linkedin.ugc.ShareContent': {
        shareCommentary: { text: content },
        shareMediaCategory: 'NONE'
      }
    },
    visibility: { 'com.linkedin.ugc.MemberNetworkVisibility': 'PUBLIC' }
  }, {
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'X-Restli-Protocol-Version': '2.0.0',
      'Content-Type': 'application/json'
    }
  });
}

/** -------------------------------------------------
 *  Background scheduler - runs every 60 seconds
 *  ------------------------------------------------- */
function startScheduler() {
  setInterval(() => {
    const now = new Date();
    const duePosts = [];
    
    // Filter posts that are due for publication
    scheduledPosts = scheduledPosts.filter(post => {
      const scheduledDate = new Date(post.scheduledAt);
      if (scheduledDate <= now && post.status === 'scheduled') {
        duePosts.push(post);
        return false; // Remove from scheduled queue
      }
      return true;
    });

    if (duePosts.length === 0) return;

    console.log(`[Scheduler] ⏰ Processing ${duePosts.length} due posts...`);

    // Iterate through all active sessions to find tokens for users with due posts
    sessionStore.all((err, sessions) => {
      if (err || !sessions) {
        console.error('[Scheduler] Failed to access session store', err);
        return;
      }

      for (const post of duePosts) {
        // Search sessions for matching userId
        const userSession = Object.values(sessions).find(s => s.user && s.user.id === post.userId);
        
        if (userSession && userSession.accessToken) {
          publishLinkedInPost(`urn:li:person:${post.userId}`, userSession.accessToken, post.content)
            .then(() => console.log(`[Scheduler] ✅ Successfully published scheduled post for ${post.userId}`))
            .catch(e => {
              console.error(`[Scheduler] ❌ Automated publish failed for ${post.userId}`, e.response?.data || e.message);
              // Re-queue on failure logic could go here
            });
        } else {
          console.error(`[Scheduler] ⚠️ Session/token not found for user ${post.userId}. Post skipped.`);
        }
      }
    });
  }, 60000); 
}

// Start the scheduler
startScheduler();

/** -------------------------------------------------
 *  ENDPOINTS
 *  ------------------------------------------------- */

app.get('/health', (req, res) => {
  res.json({ status: 'ok', serverTime: new Date().toISOString() });
});

app.get('/me', (req, res) => {
  if (req.session && req.session.user) {
    res.json(req.session.user);
  } else {
    res.status(401).json({ error: 'Session expired or not authenticated' });
  }
});

app.post('/publish', async (req, res) => {
  if (!req.session || !req.session.user || !req.session.accessToken) {
    return res.status(401).json({ error: 'Auth session required' });
  }
  const { content } = req.body;
  if (!content?.trim()) return res.status(400).json({ error: 'Empty content' });

  try {
    const memberUrn = `urn:li:person:${req.session.user.id}`;
    const response = await publishLinkedInPost(memberUrn, req.session.accessToken, content);
    res.json({ success: true, message: 'Published!', data: response.data });
  } catch (error) {
    console.error('[Publish API Error]', error.response?.data || error.message);
    res.status(error.response?.status || 500).json({ error: 'LinkedIn API error' });
  }
});

app.post('/schedule', (req, res) => {
  if (!req.session?.user) return res.status(401).json({ error: 'Auth session required' });
  const { content, scheduledAt } = req.body;
  
  if (!content || !scheduledAt) {
    return res.status(400).json({ error: 'Invalid post data' });
  }
  
  const scheduleDate = new Date(scheduledAt);
  if (scheduleDate <= new Date()) {
    return res.status(400).json({ error: 'Scheduled time must be in the future' });
  }
  
  const post = {
    id: `job-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    userId: req.session.user.id,
    content,
    scheduledAt: scheduleDate.toISOString(),
    author: { 
      name: req.session.user.name, 
      picture: req.session.user.picture 
    },
    status: 'scheduled'
  };
  
  scheduledPosts.push(post);
  console.log(`[Queue] 📅 Scheduled post for ${post.userId} at ${post.scheduledAt}`);
  res.json({ success: true, message: 'Added to queue', job: post });
});

app.get('/queue', (req, res) => {
  if (!req.session?.user) return res.status(401).json({ error: 'Auth session required' });
  const myQueue = scheduledPosts
    .filter(p => p.userId === req.session.user.id)
    .sort((a, b) => new Date(a.scheduledAt) - new Date(b.scheduledAt));
  res.json(myQueue);
});

app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ error: 'Logout failed' });
    res.clearCookie('linkgrow.sid');
    res.json({ message: 'Success' });
  });
});

app.get('/auth/linkedin/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).json({ error: 'OAuth code missing' });

  try {
    console.log('[Auth] Exchanging code for token...');
    const tokenResponse = await axios.post('https://www.linkedin.com/oauth/v2/accessToken',
      new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: REDIRECT_URI,
      }).toString(),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    const accessToken = tokenResponse.data.access_token;
    
    console.log('[Auth] Fetching user profile...');
    const profileResponse = await axios.get('https://api.linkedin.com/v2/userinfo', {
      headers: { Authorization: `Bearer ${accessToken}` }
    });

    const data = profileResponse.data;
    const userData = {
      id: data.sub || data.id,
      name: data.name || `${data.given_name} ${data.family_name}`,
      email: data.email,
      picture: data.picture || `https://ui-avatars.com/api/?name=${encodeURIComponent(data.name || 'User')}&background=0A66C2&color=fff`,
      headline: data.headline || 'LinkedIn Content Creator',
      connections: data.connections || 0
    };

    req.session.user = userData;
    req.session.accessToken = accessToken;
    
    req.session.save((err) => {
      if (err) {
        console.error('[Auth] Session save failed', err);
        return res.status(500).json({ error: 'Internal session error' });
      }
      console.log(`[Auth] ✅ User ${userData.name} authenticated successfully`);
      res.json(userData);
    });

  } catch (error) {
    console.error('[Auth Error]', error.response?.data || error.message);
    res.status(500).json({ error: 'LinkedIn authentication failed' });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`✓ LinkGrow API listening on port ${PORT}`);
});
