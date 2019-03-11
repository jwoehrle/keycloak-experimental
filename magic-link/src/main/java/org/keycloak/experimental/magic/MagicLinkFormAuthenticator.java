/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.experimental.magic;

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.security.SecureRandom;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class MagicLinkFormAuthenticator /*extends AbstractUsernameFormAuthenticator*/ implements Authenticator {

    private static final Logger LOG = Logger.getLogger(MagicLinkFormAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String expectedEmailKey = context.getAuthenticationSession().getAuthNote("loginCode");
        if (expectedEmailKey != null) {
            String requestKey = context.getHttpRequest().getUri().getQueryParameters().getFirst("loginCode");
            verifyCode(context, requestKey);
        } else {
            context.challenge(context.form().createForm("login-email-only.ftl"));
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("form-type")) {
            String type = formData.getFirst("form-type");
            if ("SMS_LOGIN".equals(type)) {
                verifyCode(context, formData.getFirst("loginCode"));
            } else if ("USERNAME".equals(type)) {
                createAndSendCode(context, formData);
            } else {
                context.failure(AuthenticationFlowError.INVALID_CLIENT_SESSION);
            }
        } else {
            context.failure(AuthenticationFlowError.CREDENTIAL_SETUP_REQUIRED);
        }


    }

    private void verifyCode(AuthenticationFlowContext context, String code) {
        String expectedCode = context.getAuthenticationSession().getAuthNote("loginCode");
        if (expectedCode != null) {
            if (expectedCode.equals(code)) {
                context.success();
            } else {
                context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
            }
        } else {
            context.challenge(context.form().createForm("login-email-only.ftl"));
        }
    }

    private void createAndSendCode(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        String email = formData.getFirst("email");
        UserModel user = context.getSession().users().getUserByEmail(email, context.getRealm());

        if (user == null) {
            context.failure(AuthenticationFlowError.UNKNOWN_USER);
        } else {
            int randomInt = new SecureRandom().nextInt(1000000);
            String loginCode = String.format("%06d", randomInt);

            context.getAuthenticationSession().setAuthNote("loginCode", loginCode);
            try {
                if ( user.getFirstAttribute("mobileNumber") != null ) {
                    sendSMS(loginCode, user.getFirstAttribute("mobileNumber"));
                } else {
                    LOG.infov( "User with id %s does not have a mobile number set. Not sending sms code", user.getId() );
                }
                String link = KeycloakUriBuilder.fromUri(context.getRefreshExecutionUrl()).queryParam("loginCode", loginCode).build().toString();
                String body = "<a href=\"" + link + "\">Click to login</a><br/><p>Your code is " + loginCode + "</p>";

                context.getSession().getProvider(EmailSenderProvider.class).send(context.getRealm().getSmtpConfig(), user, "Login link", null, body);
                context.setUser(user);
                context.challenge(context.form().createForm("login-sms-code.ftl"));
            } catch (EmailException e) {
                LOG.error(e);
            }
        }
    }

    private void sendSMS(String smsCode, String toNumber) {
        String twilioUser = System.getenv("TWILIO_USER");
        String twilioPassword = System.getenv("TWILIO_PASSWORD");
        String fromNumber = System.getenv("TWILIO_FROM");
        if ( twilioUser != null && twilioPassword != null && toNumber != null && fromNumber != null ) {
            Twilio.init(twilioUser, twilioPassword);
            Message.creator(new PhoneNumber(toNumber), new PhoneNumber(fromNumber),"Your code: " + smsCode).create();
        } else {
            LOG.error("Cannot send SMS via twilio. Twilio setup is incomplete, make sure all required properties are set in env");
        }

    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }


}
