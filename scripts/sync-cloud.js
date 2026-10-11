#!/usr/bin/env node
const db = require('../db');
const { syncWithCloudServer } = require('../server');

(async () => {
    try {
        console.log('[SYNC] Initializing database...');
        await db.initDatabase();
        console.log('[SYNC] Starting bidirectional synchronization with Render Cloud...');
        const res = await syncWithCloudServer();
        console.log('[SYNC] Synchronization completed successfully:');
        console.log(`       Imported locally from Cloud: ${res.importedLocally}`);
        console.log(`       Pushed to Cloud from Local:  ${res.pushedToCloud}`);
        console.log(`       Purged deleted keys:         ${res.purgedFromCloud}`);
        process.exit(0);
    } catch (err) {
        console.error('[SYNC] Sync error:', err.message);
        // Do not crash build scripts if cloud instance is temporarily unreachable
        process.exit(0);
    }
})();
