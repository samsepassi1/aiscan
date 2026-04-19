// aiscan test fixture — should trigger AI-SEC-002 (Missing Authorization)
// DO NOT USE IN PRODUCTION

const express = require('express');
const app = express();
const router = express.Router();

// VULNERABLE 1: Express admin route with no middleware
app.get('/admin/dashboard', (req, res) => {
    res.json({ users: [] });
});

// VULNERABLE 2: Express DELETE with no auth
router.delete('/api/user/:id', async (req, res) => {
    await User.findByIdAndDelete(req.params.id);
    res.json({ deleted: req.params.id });
});

// VULNERABLE 3: Express POST on sensitive path
app.post('/api/posts', async (req, res) => {
    const post = await Post.create(req.body);
    res.status(201).json(post);
});

// VULNERABLE 4: User-specific data access, no auth check
router.get('/user/:userId/settings', (req, res) => {
    res.json({ userId: req.params.userId });
});

// VULNERABLE 5: Payment endpoint no auth
app.post('/api/payment/charge', async (req, res) => {
    res.json({ charged: true });
});

// SAFE 1: Named middleware in argument position — should NOT be flagged
app.get('/admin/reports', requireAuth, (req, res) => {
    res.json({ reports: [] });
});

// SAFE 2: Manual auth check in handler — should NOT be flagged
app.delete('/api/comment/:id', async (req, res) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    res.json({ deleted: req.params.id });
});

// SAFE 3: Public endpoint — should NOT be flagged
app.get('/api/public/posts', (req, res) => {
    res.json([]);
});

// SAFE 4: Health check — should NOT be flagged
app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
});
