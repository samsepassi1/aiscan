// aiscan test fixture — should NOT trigger AI-SEC-002
// Demonstrates properly authorized route handlers

const express = require('express');
const { requireAuth, authorize } = require('./middleware/auth');
const app = express();
const router = express.Router();

// Named middleware in argument slot — safe
app.get('/admin/dashboard', requireAuth, (req, res) => {
    res.json({ users: [] });
});

// Multiple middleware — safe
router.delete('/api/user/:id', authenticate, authorize('admin'), async (req, res) => {
    await User.findByIdAndDelete(req.params.id);
    res.json({ deleted: req.params.id });
});

// Manual req.user check — safe
app.delete('/api/comment/:id', async (req, res) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    res.json({ deleted: req.params.id });
});

// Session check — safe
router.get('/user/:userId/settings', (req, res) => {
    if (!req.session || !req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    res.json({ userId: req.params.userId });
});

// Public endpoints — correctly have no auth
app.get('/api/public/posts', (req, res) => {
    res.json([]);
});

app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
});
