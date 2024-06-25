{{- define "shibboleth2-conf" }}
<SPConfig xmlns="urn:mace:shibboleth:3.0:native:sp:config"
    xmlns:conf="urn:mace:shibboleth:3.0:native:sp:config"
    clockSkew="180">

    <OutOfProcess tranLogFormat="%u|%s|%IDP|%i|%ac|%t|%attr|%n|%b|%E|%S|%SS|%L|%UA|%a" />
    <UnixListener address="/var/run/shibboleth/shibd.sock"/>

    <!--
    By default, in-memory StorageService, ReplayCache, ArtifactMap, and SessionCache
    are used. See example-shibboleth2.xml for samples of explicitly configuring them.
    -->

    <!-- The ApplicationDefaults element is where most of Shibboleth's SAML bits are defined. -->
    <ApplicationDefaults entityID="{{ .Values.shibd.entity_id | default "https://my-sp.example.org/shibboleth" }}"
        REMOTE_USER="{{ .Values.shibd.remote_user | default "eppn persistent-id" }}"
        cipherSuites="DEFAULT:!EXP:!LOW:!aNULL:!eNULL:!DES:!IDEA:!SEED:!RC4:!3DES:!kRSA:!SSLv2:!SSLv3:!TLSv1:!TLSv1.1">

        <!--
        Controls session lifetimes, address checks, cookie handling, and the protocol handlers.
        Each Application has an effectively unique handlerURL, which defaults to "/Shibboleth.sso"
        and should be a relative path, with the SP computing the full value based on the virtual
        host. Using handlerSSL="true" will force the protocol to be https. You should also set
        cookieProps to "https" for SSL-only sites. Note that while we default checkAddress to
        "false", this makes an assertion stolen in transit easier for attackers to misuse.
        -->
        <Sessions lifetime="{{ .Values.shibd.session_lifetime | default 28800 }}" timeout="{{ .Values.shibd.session_timeout | default 3600 }}" relayState="ss:mem"
                  checkAddress="false" handlerSSL="{{ .Values.shibd.handlerSSL | default true }}" cookieProps="{{ .Values.shibd.cookieProps | default "https" }}"
                  consistentAddress="{{ .Values.shibd.consistentAddress | default true }}">

            <!--
            Configures SSO for a default IdP. To properly allow for >1 IdP, remove
            entityID property and adjust discoveryURL to point to discovery service.
            You can also override entityID on /Login query string, or in RequestMap/htaccess.
            -->
            <SSO discoveryProtocol="SAMLDS" discoveryURL="https://ds.aaf.edu.au/discovery/DS">
              SAML2
            </SSO>

            <!-- SAML and local-only logout. -->
            <Logout>SAML2 Local</Logout>

            <SessionInitiator type="Chaining" Location="/DS-AAF" id="DS-AAF">
              <SessionInitiator type="SAML2" acsIndex="1" template="bindingTemplate.html"/>
              <SessionInitiator type="SAMLDS" URL="https://ds.aaf.edu.au/discovery/DS"/>
            </SessionInitiator>

            <SessionInitiator type="Chaining" Location="/DS-Tuakiri" id="DS-Tuakiri">
              <SessionInitiator type="SAML2" acsIndex="1" template="bindingTemplate.html"/>
              <SessionInitiator type="SAMLDS" URL="https://directory.tuakiri.ac.nz/ds/DS"/>
            </SessionInitiator>

            <SessionInitiator type="Chaining" Location="/UniMelb" id="UniMelb"
                              entityID="https://idp.unimelb.edu.au/idp/shibboleth">
              <SessionInitiator type="SAML2" acsIndex="1" template="bindingTemplate.html"/>
            </SessionInitiator>

            <!-- Administrative logout. -->
            <LogoutInitiator type="Admin" Location="/Logout/Admin" acl="127.0.0.1 ::1" />

            <!-- Extension service that generates "approximate" metadata based on SP configuration. -->
            <Handler type="MetadataGenerator" Location="/Metadata" signing="false"/>

            <!-- Status reporting service. -->
            <Handler type="Status" Location="/Status" acl="127.0.0.1 ::1"/>

            <!-- Session diagnostic service. -->
            <Handler type="Session" Location="/Session" showAttributeValues="false"/>

            <!-- JSON feed of discovery information. -->
            <Handler type="DiscoveryFeed" Location="/DiscoFeed"/>
        </Sessions>

        <!--
        Allows overriding of error template information/filenames. You can
        also add your own attributes with values that can be plugged into the
        templates, e.g., helpLocation below.
        -->
        <Errors supportContact="support@rc.nectar.org.au"
            helpLocation="/about.html"
            styleSheet="/shibboleth-sp/main.css"/>

        <MetadataProvider type="XML" validate="true"
                          url="https://md.aaf.edu.au/aaf-metadata.xml"
                          backingFilePath="metadata.aaf.xml" maxRefreshDelay="7200">
          <MetadataFilter type="RequireValidUntil" maxValidityInterval="2419200"/>
          <MetadataFilter type="Signature" certificate="/etc/shibboleth/aafcert.pem" verifyBackup="false"/>
          <DiscoveryFilter type="Blacklist" matcher="EntityAttributes" trimTags="true"
                           attributeName="http://macedir.org/entity-category"
                           attributeNameFormat="urn:oasis:names:tc:SAML:3.0:attrname-format:uri"
                           attributeValue="http://refeds.org/category/hide-from-discovery" />
        </MetadataProvider>

        <MetadataProvider type="XML" validate="true"
                          url="https://directory.tuakiri.ac.nz/metadata/tuakiri-metadata-signed.xml"
                          backingFilePath="metadata.tuakiri.xml" maxRefreshDelay="7200">
          <MetadataFilter type="RequireValidUntil" maxValidityInterval="2419200"/>
          <MetadataFilter type="Signature" certificate="/etc/shibboleth/tuakiricert.pem" verifyBackup="false"/>
          <DiscoveryFilter type="Blacklist" matcher="EntityAttributes" trimTags="true"
                           attributeName="http://macedir.org/entity-category"
                           attributeNameFormat="urn:oasis:names:tc:SAML:3.0:attrname-format:uri"
                           attributeValue="http://refeds.org/category/hide-from-discovery" />
        </MetadataProvider>

        <!-- Example of remotely supplied "on-demand" signed metadata. -->
        <!--
        <MetadataProvider type="MDQ" validate="true" cacheDirectory="mdq"
                baseUrl="http://mdq.federation.org" ignoreTransport="true">
            <MetadataFilter type="RequireValidUntil" maxValidityInterval="2419200"/>
            <MetadataFilter type="Signature" certificate="mdqsigner.pem" />
        </MetadataProvider>
        -->

        <!-- Map to extract attributes from SAML assertions. -->
        <AttributeExtractor type="XML" validate="true" reloadChanges="false" path="attribute-map.xml"/>

        <!-- Default filtering policy for recognized attributes, lets other data pass. -->
        <AttributeFilter type="XML" validate="true" path="attribute-policy.xml"/>

        <!-- Simple file-based resolvers for separate signing/encryption keys. -->
        <CredentialResolver type="File" use="signing"
            key="/vault/secrets/backendkey.pem" certificate="/vault/secrets/backendcert.pem"/>
        <CredentialResolver type="File" use="encryption"
            key="/vault/secrets/backendkey.pem" certificate="/vault/secrets/backendcert.pem"/>

    </ApplicationDefaults>

    <!-- Policies that determine how to process and authenticate runtime messages. -->
    <SecurityPolicyProvider type="XML" validate="true" path="security-policy.xml"/>

    <!-- Low-level configuration about protocols and bindings available for use. -->
    <ProtocolProvider type="XML" validate="true" reloadChanges="false" path="protocols.xml"/>

</SPConfig>

{{- end }}
