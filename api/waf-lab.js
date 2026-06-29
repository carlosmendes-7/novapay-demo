const demoHandler = require('./_demo-handler');

module.exports = async (req, res) => {
  return demoHandler(req, res, 'waf-lab');
};
