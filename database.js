const mysql = require('mysql2/promise');

console.log('Database Configuration:');
console.log(`  Host: ${process.env.DB_HOST}`);
console.log(`  User: ${process.env.DB_USER}`);
console.log(`  Database: ${process.env.DB_NAME}`);
console.log(`  Port: ${process.env.DB_PORT || 3306}`);

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0,
  multipleStatements: false, 
  connectTimeout: 10000,
  charset: 'utf8mb4'
});

console.log('Attempting to connect to database...');
pool.getConnection()
  .then(connection => {
    console.log('✓ Database connected successfully');
    connection.release();
  })
  .catch(err => {
    console.error('✗ Database connection failed:');
    console.error(`  Error: ${err.message}`);
    console.error(`  Code: ${err.code}`);
    console.error(`  Host: ${err.address || 'N/A'}`);
    console.error(`  Port: ${err.port || 'N/A'}`);
    console.error('\nPlease check:');
    console.error('  1. Database server is running');
    console.error('  2. Host and port are correct in .env');
    console.error('  3. Firewall allows connection from this server');
    console.error('  4. Database user has remote access permissions');
    process.exit(1);
  });

module.exports = pool;
