const demoHandler = require('./_demo-handler');

module.exports = async (req, res) => {
  const slug = Array.isArray(req.query.slug) ? req.query.slug.join('/') : req.query.slug;
  return demoHandler(req, res, slug);
};
