// TODO:
//  - test with database names, table names and column names that contain spaces, commas and braces

import {parse} from '../src/index'
import {expect, config} from 'chai'


config.truncateThreshold = 0




describe('mysql-grants unit tests', (): void => {
	it('validates parameter', () => {
		expect(() => parse()).to.throw()
		expect(() => parse(null)).to.throw()
		expect(() => parse(123)).to.throw()
		expect(() => parse([1,2])).to.throw()
		expect(() => parse(['x', null])).to.throw()
	})

	it('test', () => {
		// Global privileges
		expect(parse([
			`GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost' WITH GRANT OPTION`
		])).to.deep.equal({
			privileges: [{
				privilege: 'ALL PRIVILEGES',
				databaseName: '*',
				tableName: '*',
				columnName: null,
			}]
		})

		// Database privileges
		expect(parse([
			`GRANT SELECT, INSERT ON db1.* TO 'root'@'localhost'`
		])).to.deep.equal({
			privileges: [{
				privilege: 'SELECT',
				databaseName: 'db1',
				tableName: '*',
				columnName: null,
			}, {
				privilege: 'INSERT',
				databaseName: 'db1',
				tableName: '*',
				columnName: null,
			}]
		})

		// Table privileges
		expect(parse([
			`GRANT SELECT, INSERT, UPDATE ON *.t1 TO u1`
		])).to.deep.equal({
			privileges: [{
				privilege: 'SELECT',
				databaseName: '*',
				tableName: 't1',
				columnName: null,
			}, {
				privilege: 'INSERT',
				databaseName: '*',
				tableName: 't1',
				columnName: null,
			}, {
				privilege: 'UPDATE',
				databaseName: '*',
				tableName: 't1',
				columnName: null,
			}]
		})

		expect(parse([
			`GRANT ALL PRIVILEGES ON db1.t1 TO 'someuser'@'somehost'`,
			`GRANT SELECT, INSERT ON db2.* TO 'someuser'@'somehost'`,
		])).to.deep.equal({
			privileges: [{
				privilege: 'ALL PRIVILEGES',
				databaseName: 'db1',
				tableName: 't1',
				columnName: null,
			}, {
				privilege: 'SELECT',
				databaseName: 'db2',
				tableName: '*',
				columnName: null,
			}, {
				privilege: 'INSERT',
				databaseName: 'db2',
				tableName: '*',
				columnName: null,
			}]
		})

		// Column privileges
		expect(parse([
			`GRANT SELECT (col1), INSERT (col1, col2) ON mydb.mytbl TO 'someuser'@'somehost'`
		])).to.deep.equal({
			privileges: [{
				privilege: 'SELECT',
				databaseName: 'mydb',
				tableName: 'mytbl',
				columnName: 'col1',
			}, {
				privilege: 'INSERT',
				databaseName: 'mydb',
				tableName: 'mytbl',
				columnName: 'col1',
			}, {
				privilege: 'INSERT',
				databaseName: 'mydb',
				tableName: 'mytbl',
				columnName: 'col2',
			}]
		})

		// Stored Routine Privileges
		// expect(parse([
		// 	`GRANT CREATE ROUTINE ON mydb.* TO 'someuser'@'somehost'`,
		// 	`GRANT EXECUTE ON PROCEDURE mydb.myproc TO 'someuser'@'somehost'`,
		// ])).to.deep.equal({
		// })
		// expect(parse([
		// 	`GRANT EXECUTE ON PROCEDURE `test2`.`triple` TO 'readonly'@'localhost'`,
		// 	`GRANT EXECUTE ON FUNCTION `test2`.`triple` TO 'readonly'@'localhost'`,
		// ])).to.deep.equal({
		// })

		// Proxy User Privileges
		// expect(parse([
		// 	`GRANT PROXY ON 'localuser'@'localhost' TO 'externaluser'@'somehost';`
		// ])).to.deep.equal({
		// })

		// Granting Roles
		// expect(parse([
		// 	`GRANT 'role1', 'role2' TO 'user1'@'localhost', 'user2'@'localhost';`
		// ])).to.deep.equal({
		// })

		// expect(parse([
		// 	``
		// ])).to.deep.equal({
		// })
	})
})