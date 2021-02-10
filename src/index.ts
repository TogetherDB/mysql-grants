/*

TODO:
	- everything
	- support partial revokes for MySQL 8.0.16+, see https://dev.mysql.com/doc/refman/8.0/en/grant.html
	- support proxy grants
	- support role grants
	- support AS clause
	- support functions/routines
*/




/*
Syntax:

GRANT
	priv_type [(column_list)]
	  [, priv_type [(column_list)]] ...
	ON [object_type] priv_level
	TO user_or_role [, user_or_role] ...
	[WITH GRANT OPTION]
	[AS user
		[WITH ROLE
			DEFAULT
		  | NONE
		  | ALL
		  | ALL EXCEPT role [, role ] ...
		  | role [, role ] ...
		]
	]
}

GRANT PROXY ON user_or_role
	TO user_or_role [, user_or_role] ...
	[WITH GRANT OPTION]

GRANT role [, role] ...
	TO user_or_role [, user_or_role] ...
	[WITH ADMIN OPTION]

object_type: {
	TABLE
  | FUNCTION
  | PROCEDURE
}

priv_level: {
	*
  | *.*
  | db_name.*
  | db_name.tbl_name
  | tbl_name
  | db_name.routine_name
}

user_or_role: {
	user (see Section 6.2.4, “Specifying Account Names”)
  | role (see Section 6.2.5, “Specifying Role Names”)
}



Global privileges:
	all?

Database level privileges:
	CREATE, DROP, EVENT, GRANT OPTION, LOCK TABLES, REFERENCES

Table level privileges:
	ALTER, CREATE VIEW, CREATE, DELETE, DROP, GRANT OPTION, INDEX, INSERT, REFERENCES, SELECT, SHOW VIEW, TRIGGER, UPDATE

Column level privileges:
	 INSERT, REFERENCES, SELECT, UPDATE
*/



import * as splitOuter from 'split-outer'


type MysqlPrivilege =
	'ALL PRIVILEGES' |
	// column privileges
	'SELECT' | 'INSERT' | 'UPDATE' | 'REFERENCES' |
	// table privileges
	'ALTER' | 'CREATE VIEW' | 'CREATE' | 'DELETE' | 'DROP' | 'GRANT OPTION' | 'INDEX' | 'SHOW VIEW' | 'TRIGGER' |
	// database privileges
	'EVENT' | 'LOCK TABLES'


type MysqlPrivilegeGrant = {
	databaseName: string
	tableName: string
	columnName: string
	privilege: MysqlPrivilege
}

type MysqlGrantSet = {
	privileges: Array<MysqlPrivilegeGrant>
}


function cleanIdentifier(s) {
	if (s.length>2 && s[0]==='`' && s[s.length-1]==='`') {
		return s.substr(1, s.length-2)
	}
	return s
}


// function parseLine(grant: string): MysqlGrantEntry {
// 	// see https://dev.mysql.com/doc/refman/8.0/en/grant.html
// 	let r

	// if (grant.endsWith(';')) {
	// 	grant = grant.substr(0, grant.length-1)
	// }

	// Proxy grants. Syntax:
	// GRANT PROXY ON user_or_role
	// TO user_or_role [, user_or_role] ...
	// [WITH GRANT OPTION]
	// const proxyGrantRegex = /^GRANT PROXY ON (.*) TO (.*?)(WITH GRANT OPTION)?;?$/
	// r = proxyGrantRegex.exec(grant)
	// if (r) {
	// 	return {
	// 		text: grant,
	// 		type: 'proxy',
	// 		proxy: r[1], // ??
	// 		grantees: r[2].split(',').map(s => s.trim()),
	// 		withGrantOption: r[3]==='WITH GRANT OPTION',
	// 	}
	// }

	// const normalGrantRegex = /^GRANT (.*) ON (.*) TO (.*?)(WITH GRANT OPTION)?;?$/
	// r = normalGrantRegex.exec(grant)
	// if (r) {
	// 	return {
	// 		text: grant,
	// 		type: 'tables',
	// 		privileges: r[1].split(',').map(s => s.trim().toUpperCase()).filter(s => s!=='USAGE'),
	// 		database: cleanIdentifier(r[2].split('.')[0]),
	// 		table: cleanIdentifier(r[2].split('.')[1]),
	// 		grantees: r[3].split(',').map(s => s.trim()),
	// 		withGrantOption: r[4]==='WITH GRANT OPTION',
	// 	}
	// }

	// const roleGrantRegex = /^GRANT (.*) TO (.*?)(WITH ADMIN OPTION)?;?$/
	// r = roleGrantRegex.exec(grant)
	// if (r) {
	// 	return {
	// 		text: grant,
	// 		type: 'role',
	// 		roles: r[1].split(',').map(s => s.trim()),
	// 		grantees: r[2].split(',').map(s => s.trim()),
	// 		withAdminOption: r[3]==='WITH ADMIN OPTION',
	// 	}
	// }

// 	// TODO: column level: GRANT SELECT (col1), INSERT (col1, col2) ON mydb.mytbl TO 'someuser'@'somehost';

// 	return {
// 		text: grant,
// 	}
// }



export function parse(lines: Array<string>): MysqlGrantSet {
	// validate parameters
	if (arguments.length !== 1) {
		throw new Error('mysql-grants.parse: Specify exactly one parameter, not '+arguments.length)
	}
	if (typeof lines!=='object' || !Array.isArray(lines)) {
		throw new Error('mysql-grants.parse: Parameter must be an Array of strings')
	}
	for (const line of lines) {
		if (typeof line !== 'string') {
			throw new Error('mysql-grants.parse: Parameter must be an Array of strings')
		}
	}

	const privileges: Array<MysqlPrivilegeGrant> = []
	for (const line of lines) {
		const grantRegex = /^GRANT (.*) ON (.*) TO (.*?)(WITH GRANT OPTION)?;?$/
		const grantRegexResult = grantRegex.exec(line)
		if (grantRegexResult) {
			// ON XXX
			let privObj = grantRegexResult[2]
			if (privObj.startsWith('TABLE')) {
				privObj = privObj.substr('TABLE'.length + 1)
			}
			if (privObj.startsWith('FUNCTION')) {
				continue // we ignore function privileges for now
				//privObj = privObj.substr('FUNCTION'.length + 1)
			}
			if (privObj.startsWith('PROCEDURE')) {
				continue // we ignore procedure privileges for now
				//privObj = privObj.substr('PROCEDURE'.length + 1)
			}
			// now privObj is * | *.* | db_name.* | db_name.tbl_name | tbl_name | db_name.routine_name
			const privObjParts = privObj.split('.')
			const databaseName = privObjParts[0]
			const tableName = privObjParts[1]

			// TO XXX
			//const grantees = grantRegexResult[3].split(',').map(s => s.trim())

			// [WITH GRANT OPTION]
			//const withGrantOption = grantRegexResult[4]==='WITH GRANT OPTION'

			// GRANT XXX (comes last so the above `continue` statements short out)
			const privList = splitOuter(grantRegexResult[1], {separators: ',', trim: true}).map(s => s.trim())
			// might be either privileges ("SELECT", "INSERT") or privileges on columns ("INSERT (ref2), UPDATE (ref3)")
			for (const privEntry of privList) {
				const privRegex = /^([A-Z ]+)( \(.+\))?$/
				const privRegexResult = privRegex.exec(privEntry)
				if (!privRegexResult) {
					// TOOD: WARNING?? If this happens we implemented the spec wrong
					continue
				}
				const privilege = privRegexResult[1] as MysqlPrivilege
				let columnNames = [null]
				if (privRegexResult[2]) {
					const rawColumnNames = privRegexResult[2].substr(2, privRegexResult[2].length-3)
					columnNames = splitOuter(rawColumnNames, {separators: ',', trim: true})
				}
				for (const columnName of columnNames) {
					privileges.push({
						databaseName,
						tableName,
						columnName,
						privilege
					})
				}
			}
		}
	}
	return {privileges}
}



export function checkPermission(grants: MysqlGrantSet, databaseName: string, tableName: string, privilege: Array<MysqlPrivilege>|MysqlPrivilege|'ALL PRIVILEGES'): boolean {
	for (const privGrant of grants.privileges) {
		// TODO
		// const tablesGrant = grant.type==='tables'? <MysqlTablesGrantEntry>grant : null
		// if (tablesGrant && (tablesGrant.database==='*' || tablesGrant.database===databaseName) && (tablesGrant.table==='*' || tablesGrant.table===tableName)) {
		// 	let privMatch: boolean
		// 	if (Array.isArray(privilege)) {
		// 		let allMatch = true
		// 		for (const priv of privilege) {
		// 			if (!this.checkPrivileges(databaseName, tableName, priv)) {
		// 				allMatch = false
		// 				break
		// 			}
		// 		}
		// 		privMatch = allMatch
		// 	} else {
		// 		privMatch = tablesGrant.privileges.indexOf(privilege)!==-1 || tablesGrant.privileges.indexOf('ALL PRIVILEGES')!==-1
		// 	}
		// 	if (privMatch) {
		// 		return true
		// 	}
		// }
	}
	return false
}

