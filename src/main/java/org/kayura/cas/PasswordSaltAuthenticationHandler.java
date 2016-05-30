package org.kayura.cas;

import java.security.GeneralSecurityException;
import java.util.Map;

import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.FailedLoginException;
import javax.sql.DataSource;
import javax.validation.constraints.NotNull;

import org.jasig.cas.adaptors.jdbc.AbstractJdbcUsernamePasswordAuthenticationHandler;
import org.jasig.cas.authentication.HandlerResult;
import org.jasig.cas.authentication.PreventedException;
import org.jasig.cas.authentication.UsernamePasswordCredential;
import org.jasig.cas.authentication.handler.PasswordEncoder;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;

public class PasswordSaltAuthenticationHandler extends AbstractJdbcUsernamePasswordAuthenticationHandler {

	private static final String DEFAULT_PASSWORD_FIELD = "password";
	private static final String DEFAULT_SALT_FIELD = "salt";

	@NotNull
	protected final String sql;
	@NotNull
	protected String passwordFieldName = DEFAULT_PASSWORD_FIELD;
	@NotNull
	protected String saltFieldName = DEFAULT_SALT_FIELD;
	protected String staticSalt;

	public PasswordSaltAuthenticationHandler(DataSource datasource, String sql) {
		super();
		setDataSource(datasource);
		this.sql = sql;
	}

	@Override
	protected final HandlerResult authenticateUsernamePasswordInternal(
			final UsernamePasswordCredential transformedCredential)
			throws GeneralSecurityException, PreventedException {
		
		final String username = getPrincipalNameTransformer().transform(transformedCredential.getUsername());
		final String encodedPsw = transformedCredential.getPassword();

		try {
			final Map<String, Object> values = getJdbcTemplate().queryForMap(this.sql, username);
			final String digestedPassword = digestEncodedPassword(encodedPsw, values);

			if (!values.get(this.passwordFieldName).equals(digestedPassword)) {
				throw new FailedLoginException("Password does not match value on record.");
			}
			return createHandlerResult(transformedCredential, this.principalFactory.createPrincipal(username), null);

		} catch (final IncorrectResultSizeDataAccessException e) {
			if (e.getActualSize() == 0) {
				throw new AccountNotFoundException(username + " not found with SQL query");
			} else {
				throw new FailedLoginException("Multiple records found for " + username);
			}
		} catch (final DataAccessException e) {
			throw new PreventedException("SQL exception while executing query for " + username, e);
		}

	}

	protected String digestEncodedPassword(String encodedPassword, Map<String, Object> values) {

		PasswordEncoder passwordEncoder = this.getPasswordEncoder();

		if (!values.containsKey(this.saltFieldName)) {
			throw new RuntimeException("Specified field name for salt does not exist in the results");
		}

		final String dynaSalt = values.get(this.saltFieldName).toString();
		final String rawPassword = mergePasswordAndSalt(encodedPassword, dynaSalt, true);

		return passwordEncoder.encode(rawPassword);
	}

	protected String mergePasswordAndSalt(String password, Object salt, boolean strict) {

		if (password == null) {
			password = "";
		}

		if (strict && (salt != null)) {
			if ((salt.toString().lastIndexOf("{") != -1) || (salt.toString().lastIndexOf("}") != -1)) {
				throw new IllegalArgumentException("Cannot use { or } in salt.toString()");
			}
		}

		if ((salt == null) || "".equals(salt)) {
			return password;
		} else {
			return password + "{" + salt.toString() + "}";
		}
	}

	public final void setStaticSalt(final String staticSalt) {
		this.staticSalt = staticSalt;
	}

	public final void setPasswordFieldName(final String passwordFieldName) {
		this.passwordFieldName = passwordFieldName;
	}

	public final void setSaltFieldName(final String saltFieldName) {
		this.saltFieldName = saltFieldName;
	}

}
