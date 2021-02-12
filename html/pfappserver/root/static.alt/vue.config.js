const { BundleAnalyzerPlugin } = require('webpack-bundle-analyzer')

module.exports = {
  publicPath: '/admin/alt',
  outputDir: 'dist',
  indexPath: 'index.html',
  css: {
    sourceMap: process.env.VUE_APP_DEBUG === 'true',
    extract: process.env.VUE_APP_DEBUG !== 'true',
    loaderOptions: {
      sass: {
        includePaths: ['node_modules', 'src/styles'],
        data: [
          `@import "bootstrap/scss/functions";`,
          `@import "bootstrap/scss/mixins/border-radius";`,
          `@import "bootstrap/scss/mixins/box-shadow";`,
          `@import "bootstrap/scss/mixins/breakpoints";`,
          `@import "bootstrap/scss/mixins/transition";`,
          `@import "variables";`
        ].join('')
      }
    }
  },
  pluginOptions: {
    i18n: {
      locale: 'en',
      fallbackLocale: 'en',
      localeDir: 'locales',
      enableInSFC: false
    }
  },
  chainWebpack: config => {
    if (process.env.VUE_APP_DEBUG === 'true') {
      config.optimization.minimize(false)
      config.optimization.delete('minimizer')
    }
  },
  configureWebpack: config => {
    if (process.env.VUE_APP_DEBUG === 'true') {
      config.plugins.push(new BundleAnalyzerPlugin({
        analyzerMode: 'static',
        openAnalyzer: false
      }))
    }
  },
  runtimeCompiler: true
}
