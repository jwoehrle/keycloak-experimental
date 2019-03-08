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

    @Override
    public void authenticate(AuthenticationFlowContext context) {
//        String expectedEmailKey = context.getAuthenticationSession().getAuthNote("email-key");
        String expectedEmailKey = context.getAuthenticationSession().getAuthNote("sms-key");
        if (expectedEmailKey != null) {
            String requestKey = context.getHttpRequest().getUri().getQueryParameters().getFirst("sms-key");
            if (requestKey == null ) {
                requestKey = context.getHttpRequest().getDecodedFormParameters().getFirst("sms-key");
            }
            if (requestKey != null) {
                if (requestKey.equals(expectedEmailKey)) {
                    context.success();
                } else {
                    context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
                }
            } else {
                context.challenge(context.form().createForm("login-sms-code.ftl"));
                // TODO add possibiliy to reset code
            }
        } else {
            context.challenge(context.form().createForm("login-email-only.ftl"));
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String email = formData.getFirst("email");
        UserModel user;
        if ( email != null ) {
            user = context.getSession().users().getUserByEmail(email, context.getRealm());
        } else {
            user = context.getUser();
        }

        if (user == null) {
            // Register user
            user = context.getSession().users().addUser(context.getRealm(), email);
            user.setEnabled(true);
            user.setEmail(email);

            // Uncomment the following line to require user to update profile on first login
            // user.addRequiredAction(UserModel.RequiredAction.UPDATE_PROFILE);
        }

        String key = KeycloakModelUtils.generateId();
        //context.getAuthenticationSession().setAuthNote("email-key", key);
        int randomInt = new SecureRandom().nextInt(1000000);
        String smsCode = String.format("%06d", randomInt);
        context.getAuthenticationSession().setAuthNote("sms-key", smsCode);

        //sendSMS(smsCode);


        String link = KeycloakUriBuilder.fromUri(context.getRefreshExecutionUrl()).queryParam("key", key).queryParam("sms-key", smsCode).build().toString();

        String body = "<a href=\"" + link + "\">Click to login</a><br/><p>Your code is "  + smsCode + "</p>";
        try {
            context.getSession().getProvider(EmailSenderProvider.class).send(context.getRealm().getSmtpConfig(), user, "Login link", null, body);
        } catch (EmailException e) {
            e.printStackTrace();
        }

        context.setUser(user);
        context.challenge(context.form().createForm("login-sms-code.ftl"));
    }

    private void sendSMS(String smsCode) {
        String twilioUser = System.getenv("TWILIO_USER");
        String twilioPassword = System.getenv("TWILIO_PASSWORD");
        // TODO make this dynamic
        String toNumber = System.getenv("TWILIO_TO");
        String fromNumber = System.getenv("TWILIO_FROM");
        Twilio.init(twilioUser, twilioPassword);
        Message sms = Message
                .creator(new PhoneNumber(toNumber), // to
                        new PhoneNumber(fromNumber), // from
                        "Your code: " + smsCode)
                .create();
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
