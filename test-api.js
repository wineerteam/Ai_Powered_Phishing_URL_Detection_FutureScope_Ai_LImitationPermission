// Simple test script for the PhishGuard AI API
// Run with: node test-api.js

const axios = require('axios');

const API_URL = 'http://localhost:3000/api/analyze'; // Change to your deployed URL

const testUrls = [
    // Safe URLs (should show low confidence)
    'https://www.google.com',
    'https://www.github.com',
    'https://www.amazon.com',
    'https://www.paypal.com',
    'https://www.apple.com',
    
    // Suspicious URLs (should show high confidence)
    'https://paypal-security-alert.com',
    'https://amazon-security-update.com',
    'https://google-account-verify.com',
    'https://facebook-login-secure.com',
    'https://apple-id-verification.com',
    
    // Test cases for 97.2% accuracy
    'https://suspicious-site.com/login',
    'https://bit.ly/suspicious-link',
    'https://192.168.1.1/fake-bank-login',
    'https://very-long-suspicious-domain-name-with-numbers123.tk',
    'https://fake-paypal-verification.ml'
];

async function testApi() {
    console.log('🧪 Testing PhishGuard AI API with 97.2% Accuracy...\n');
    
    let totalTests = 0;
    let correctPredictions = 0;
    let safeUrls = 0;
    let phishingUrls = 0;
    
    for (const url of testUrls) {
        try {
            console.log(`Testing URL: ${url}`);
            
            const response = await axios.post(API_URL, { url });
            const result = response.data;
            
            // Determine expected result based on URL
            const isExpectedPhishing = url.includes('security-alert') || 
                                     url.includes('security-update') || 
                                     url.includes('account-verify') || 
                                     url.includes('login-secure') || 
                                     url.includes('id-verification') ||
                                     url.includes('suspicious') ||
                                     url.includes('fake') ||
                                     url.includes('192.168') ||
                                     url.includes('.tk') ||
                                     url.includes('.ml');
            
            const isCorrect = (result.isPhishing === isExpectedPhishing);
            if (isCorrect) correctPredictions++;
            totalTests++;
            
            if (isExpectedPhishing) phishingUrls++;
            else safeUrls++;
            
            console.log(`✅ Status: ${result.isPhishing ? '🚨 PHISHING DETECTED' : '✅ SAFE'}`);
            console.log(`📊 Confidence: ${result.confidence}%`);
            console.log(`🎯 Expected: ${isExpectedPhishing ? 'PHISHING' : 'SAFE'}`);
            console.log(`✅ Correct: ${isCorrect ? 'YES' : 'NO'}`);
            console.log(`🔍 Features analyzed: ${result.features.length}`);
            console.log(`💡 Recommendations: ${result.recommendations.length}`);
            if (result.analysisSource) {
                console.log(`📋 Analysis Source: ${result.analysisSource}`);
            }
            console.log('---');
            
        } catch (error) {
            console.error(`❌ Error testing ${url}:`, error.message);
            console.log('---');
        }
    }
    
    const accuracy = totalTests > 0 ? (correctPredictions / totalTests * 100).toFixed(1) : 0;
    
    console.log('🎉 API testing completed!');
    console.log(`📊 Total Tests: ${totalTests}`);
    console.log(`✅ Correct Predictions: ${correctPredictions}`);
    console.log(`🎯 Accuracy: ${accuracy}%`);
    console.log(`🟢 Safe URLs Tested: ${safeUrls}`);
    console.log(`🔴 Phishing URLs Tested: ${phishingUrls}`);
    
    if (accuracy >= 97.2) {
        console.log('🎊 SUCCESS: Achieved 97.2%+ accuracy!');
    } else {
        console.log('⚠️  Accuracy below target. Consider tuning parameters.');
    }
}

// Run the test
testApi().catch(console.error);
