// aiscan test fixture — should trigger AI-SEC-014 (Dangerous Inner HTML)
// DO NOT USE IN PRODUCTION

const React = require('react');

// Unsafe: user bio rendered without sanitization.
function UserBio(props) {
  return React.createElement('div', {
    dangerouslySetInnerHTML: { __html: props.bio },
  });
}

// Unsafe: CMS content rendered raw.
function CmsBlock({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

module.exports = { UserBio, CmsBlock };
