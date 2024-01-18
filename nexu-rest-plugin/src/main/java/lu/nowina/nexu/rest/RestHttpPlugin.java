/**
 * © Nowina Solutions, 2015-2015
 *
 * Concédée sous licence EUPL, version 1.1 ou – dès leur approbation par la Commission européenne - versions ultérieures de l’EUPL (la «Licence»).
 * Vous ne pouvez utiliser la présente œuvre que conformément à la Licence.
 * Vous pouvez obtenir une copie de la Licence à l’adresse suivante:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Sauf obligation légale ou contractuelle écrite, le logiciel distribué sous la Licence est distribué «en l’état»,
 * SANS GARANTIES OU CONDITIONS QUELLES QU’ELLES SOIENT, expresses ou implicites.
 * Consultez la Licence pour les autorisations et les restrictions linguistiques spécifiques relevant de la Licence.
 */
package lu.nowina.nexu.rest;

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import lu.nowina.nexu.CancelledOperationException;
import lu.nowina.nexu.api.*;
import lu.nowina.nexu.api.flow.BasicOperationStatus;
import lu.nowina.nexu.api.flow.OperationResult;
import lu.nowina.nexu.api.plugin.*;
import lu.nowina.nexu.flow.operation.CoreOperationStatus;
import lu.nowina.nexu.flow.operation.TokenOperationResultKey;
import lu.nowina.nexu.json.GsonHelper;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.bind.DatatypeConverter;
import java.util.*;

import static org.apache.commons.lang.StringUtils.isNotBlank;

/**
 * Default implementation of HttpPlugin for NexU.
 *
 * @author David Naramski
 */
public class RestHttpPlugin implements HttpPlugin {

	private static final Logger logger = LoggerFactory.getLogger(RestHttpPlugin.class.getName());

	@Override
	public List<InitializationMessage> init(String pluginId, NexuAPI api) {
		return Collections.emptyList();
	}

	@Override
	public HttpResponse process(NexuAPI api, HttpRequest req) throws Exception {

		final String target = req.getTarget();
		logger.info("PathInfo " + target);

		final String payload = IOUtils.toString(req.getInputStream());
		logger.info("Payload '" + payload + "'");

		switch(target) {
		case "/sign":
			return signRequest(api, req, payload);
		case "/certificates":
			return getCertificates(api, req, payload);
		case "/identityInfo":
			return getIdentityInfo(api, payload);
		case "/authenticate":
			return authenticate(api, req, payload);
		default:
			throw new RuntimeException("Target not recognized " + target);
		}
	}

	protected <T> Execution<T> returnNullIfValid(NexuRequest request) {
		return null;
	}
	
	private HttpResponse signRequest(NexuAPI api, HttpRequest req, String payload) throws Exception {
		logger.info("Signature");
		final SignatureRequest r;
		if (StringUtils.isEmpty(payload)) {
			r = new SignatureRequest();

			String data = req.getParameter("dataToSign");
			if (data != null) {
				logger.info("Data to sign " + data);
				ToBeSigned tbs = new ToBeSigned();
				tbs.setBytes(DatatypeConverter.parseBase64Binary(data));
				r.setToBeSigned(tbs);
			}

			String digestAlgo = req.getParameter("digestAlgo");
			if (digestAlgo != null) {
				logger.info("digestAlgo " + digestAlgo);
				r.setDigestAlgorithm(DigestAlgorithm.forName(digestAlgo, DigestAlgorithm.SHA256));
			}

			String tokenIdString = req.getParameter("tokenId");
			if (tokenIdString != null) {
				TokenId tokenId = new TokenId(tokenIdString);
				r.setTokenId(tokenId);
			}

			String keyId = req.getParameter("keyId");
			if (keyId != null) {
				r.setKeyId(keyId);
			}
		} else {
			r = GsonHelper.fromJson(payload, SignatureRequest.class);
		}

		final HttpResponse invalidRequestHttpResponse = checkRequestValidity(api, r);
		if(invalidRequestHttpResponse != null) {
			return invalidRequestHttpResponse;
		} else {
			logger.info("Call API");
			CertificateResponseCache cache = CertificateResponseCache.getInstance();
			if (cache.getCertificateResponse() != null){
				TokenId tkId = cache.getCertificateResponse().getTokenId();
				final Map<TokenOperationResultKey, Object> map1 = new HashMap<TokenOperationResultKey, Object>();
				map1.put(TokenOperationResultKey.ADVANCED_CREATION, false);
				map1.put(TokenOperationResultKey.TOKEN_ID, tkId);
				final OperationResult<Map<TokenOperationResultKey, Object>> getTokenOperationResult =
						new OperationResult<Map<TokenOperationResultKey, Object>>(map1);
				SignatureTokenConnection token = null;
				if (getTokenOperationResult.getStatus().equals(BasicOperationStatus.SUCCESS)) {
					final Map<TokenOperationResultKey, Object> map = getTokenOperationResult.getResult();
					final TokenId tokenId = (TokenId) map.get(TokenOperationResultKey.TOKEN_ID);

					final SignatureTokenConnection signatureToken = api.getTokenConnection(tkId);
					final OperationResult<SignatureTokenConnection> getTokenConnectionOperationResult = new OperationResult<SignatureTokenConnection>(signatureToken);
					if (getTokenConnectionOperationResult.getStatus().equals(BasicOperationStatus.SUCCESS)) {
						token = getTokenConnectionOperationResult.getResult();
						logger.info("Token " + token);

						final Product product = (Product) map.get(TokenOperationResultKey.SELECTED_PRODUCT);
						final ProductAdapter productAdapter = (ProductAdapter) map.get(TokenOperationResultKey.SELECTED_PRODUCT_ADAPTER);
						final OperationResult<DSSPrivateKeyEntry> selectPrivateKeyOperationResult =
								DssPrivate(token, api, product, productAdapter, null, cache.getCertificateResponse().getKeyId());
						if (selectPrivateKeyOperationResult.getStatus().equals(BasicOperationStatus.SUCCESS)) {
							final DSSPrivateKeyEntry key = selectPrivateKeyOperationResult.getResult();

							logger.info("Key " + key + " " + key.getCertificate().getCertificate().getSubjectDN() + " from " + key.getCertificate().getCertificate().getIssuerDN());
							final OperationResult<SignatureValue> signOperationResult = new OperationResult<SignatureValue>(token.sign(r.getToBeSigned(), r.getDigestAlgorithm(), key));
							if(signOperationResult.getStatus().equals(BasicOperationStatus.SUCCESS)) {
								final SignatureValue value = signOperationResult.getResult();
//
								Execution<SignatureResponse> signatureResponseExecution = new Execution<SignatureResponse>(new SignatureResponse(value, key.getCertificate(), key.getCertificateChain()));
								return toHttpResponse(signatureResponseExecution);
							} else {
								if(signOperationResult.getStatus().equals(BasicOperationStatus.EXCEPTION)) {
									throw signOperationResult.getException();
								} else {
									return toHttpResponse(new Execution<>(signOperationResult.getStatus()));
								}
							}
						} else {
							if(selectPrivateKeyOperationResult.getStatus().equals(BasicOperationStatus.EXCEPTION)) {
								throw selectPrivateKeyOperationResult.getException();
							} else {
								return toHttpResponse(new Execution<>(selectPrivateKeyOperationResult.getStatus()));
							}
						}
					} else {
						if(getTokenConnectionOperationResult.getStatus().equals(BasicOperationStatus.EXCEPTION)) {
							throw getTokenConnectionOperationResult.getException();
						} else {
							return toHttpResponse(new Execution<>(getTokenConnectionOperationResult.getStatus()));
						}
					}
				} else {
					if(getTokenOperationResult.getStatus().equals(BasicOperationStatus.EXCEPTION)) {
						throw getTokenOperationResult.getException();
					} else {
						return toHttpResponse(new Execution<>(getTokenOperationResult.getStatus()));
					}
				}
			}
			final Execution<?> respObj = api.sign(r);
			return toHttpResponse(respObj);
		}
	}

	private HttpResponse getCertificates(NexuAPI api, HttpRequest req, String payload) {
		logger.info("API call certificates");
		final GetCertificateRequest r;
		if (StringUtils.isEmpty(payload)) {
			r = new GetCertificateRequest();

			final String certificatePurpose = req.getParameter("certificatePurpose");
			if (certificatePurpose != null) {
				logger.info("Certificate purpose " + certificatePurpose);
				final Purpose purpose = Enum.valueOf(Purpose.class, certificatePurpose);
				final CertificateFilter certificateFilter = new CertificateFilter();
				certificateFilter.setPurpose(purpose);
				r.setCertificateFilter(certificateFilter);
			}else {
				final String nonRepudiation = req.getParameter("nonRepudiation");
				if(isNotBlank(nonRepudiation)) {
					final CertificateFilter certificateFilter = new CertificateFilter();
					certificateFilter.setNonRepudiationBit(Boolean.parseBoolean(nonRepudiation));
					r.setCertificateFilter(certificateFilter);
				}
			}

			checkSaveCertificate(req, r);
		} else {
			r = GsonHelper.fromJson(payload, GetCertificateRequest.class);
			checkSaveCertificate(req, r);
		}

		final HttpResponse invalidRequestHttpResponse = checkRequestValidity(api, r);
		if(invalidRequestHttpResponse != null) {
			return invalidRequestHttpResponse;
		} else {
			CertificateResponseCache cache = CertificateResponseCache.getInstance();
			if (cache.getCertificateResponse() != null){
				CustomCertificateResponse customCertificateResponse = new CustomCertificateResponse(true, cache.getCertificateResponse());
				if (r.isDeleteCache()){
					deleteCache();
				}
				return new HttpResponse(GsonHelper.toJson(customCertificateResponse), "application/json;charset=UTF-8", HttpStatus.OK);
			}
			logger.info("Call API");
			final Execution<?> respObj = api.getCertificate(r);
			return toHttpResponse(respObj);
		}
	}

	private HttpResponse getIdentityInfo(NexuAPI api, String payload) {
		logger.info("API call get identity info");
		final GetIdentityInfoRequest r;
		if (StringUtils.isEmpty(payload)) {
			r = new GetIdentityInfoRequest();
		} else {
			r = GsonHelper.fromJson(payload, GetIdentityInfoRequest.class);
		}

		final HttpResponse invalidRequestHttpResponse = checkRequestValidity(api, r);
		if(invalidRequestHttpResponse != null) {
			return invalidRequestHttpResponse;
		} else {
			logger.info("Call API");
			final Execution<?> respObj = api.getIdentityInfo(r);
			return toHttpResponse(respObj);
		}
	}

	private HttpResponse authenticate(NexuAPI api, HttpRequest req, String payload) {
		logger.info("Authenticate");
		final AuthenticateRequest r;
		if (StringUtils.isEmpty(payload)) {
			r = new AuthenticateRequest();

			final String data = req.getParameter("challenge");
			if (data != null) {
				logger.info("Challenge " + data);
				final ToBeSigned tbs = new ToBeSigned();
				tbs.setBytes(DatatypeConverter.parseBase64Binary(data));
				r.setChallenge(tbs);
			}
		} else {
			r = GsonHelper.fromJson(payload, AuthenticateRequest.class);
		}

		final HttpResponse invalidRequestHttpResponse = checkRequestValidity(api, r);
		if(invalidRequestHttpResponse != null) {
			return invalidRequestHttpResponse;
		} else {
			logger.info("Call API");
			final Execution<?> respObj = api.authenticate(r);
			return toHttpResponse(respObj);
		}
	}

	private HttpResponse checkRequestValidity(final NexuAPI api, final NexuRequest request) {
		final Execution<Object> verification = returnNullIfValid(request);
		if(verification != null) {
			final Feedback feedback;
			if(verification.getFeedback() == null) {
				feedback = new Feedback();
				feedback.setFeedbackStatus(FeedbackStatus.SIGNATURE_VERIFICATION_FAILED);
				verification.setFeedback(feedback);
			} else {
				feedback = verification.getFeedback();
			}
			feedback.setInfo(api.getEnvironmentInfo());
			feedback.setNexuVersion(api.getAppConfig().getApplicationVersion());
			return toHttpResponse(verification);
		} else {
			return null;
		}
	}
	
	private HttpResponse toHttpResponse(final Execution<?> respObj) {
		if (respObj.isSuccess()) {
			return new HttpResponse(GsonHelper.toJson(respObj), "application/json;charset=UTF-8", HttpStatus.OK);
		} else {
			return new HttpResponse(GsonHelper.toJson(respObj), "application/json;charset=UTF-8", HttpStatus.ERROR);
		}
	}


	private OperationResult<DSSPrivateKeyEntry> DssPrivate(SignatureTokenConnection token, NexuAPI api, Product product, ProductAdapter productAdapter, CertificateFilter certificateFilter,  String keyFilter) {
		final List<DSSPrivateKeyEntry> keys;

		try {
			if((productAdapter != null) && (product != null) && productAdapter.supportCertificateFilter(product) && (certificateFilter != null)) {
				keys = productAdapter.getKeys(token, certificateFilter);
			} else {
				keys = token.getKeys();
			}
		} catch(final CancelledOperationException e) {
			return new OperationResult<DSSPrivateKeyEntry>(BasicOperationStatus.USER_CANCEL);
		}

		DSSPrivateKeyEntry key = null;

		final Iterator<DSSPrivateKeyEntry> it = keys.iterator();
		while (it.hasNext()) {
			final DSSPrivateKeyEntry e = it.next();
			if ("CN=Token Signing Public Key".equals(e.getCertificate().getCertificate().getIssuerDN().getName())) {
				it.remove();
			}
		}

		if (keys.isEmpty()) {
			return new OperationResult<DSSPrivateKeyEntry>(CoreOperationStatus.NO_KEY);
		} else if (keys.size() == 1) {
			key = keys.get(0);
			if((keyFilter != null) && !key.getCertificate().getDSSIdAsString().equals(keyFilter)) {
				return new OperationResult<DSSPrivateKeyEntry>(CoreOperationStatus.CANNOT_SELECT_KEY);
			} else {
				return new OperationResult<DSSPrivateKeyEntry>(key);
			}
		} else {
			if (keyFilter != null) {
				for (final DSSPrivateKeyEntry k : keys) {
					if (k.getCertificate().getDSSIdAsString().equals(keyFilter)) {
						key = k;
						break;
					}
				}
				if(key == null) {
					return new OperationResult<DSSPrivateKeyEntry>(CoreOperationStatus.CANNOT_SELECT_KEY);
				}
			} else {
				return new OperationResult<DSSPrivateKeyEntry>(CoreOperationStatus.CANNOT_SELECT_KEY);
			}
			return new OperationResult<DSSPrivateKeyEntry>(key);
		}
	}

	private void deleteCache() {
		// Cache the values as strings
		CertificateResponseCache cache = CertificateResponseCache.getInstance();
		cache.setCertificateResponse(null);
	}

	private void checkSaveCertificate(HttpRequest req, GetCertificateRequest r){
		if(req.getParameter("deleteCache") != null && req.getParameter("deleteCache").equals("true")){
			r.setSaveCertificate(false);
			r.setDeleteCache(true);
		} else if (req.getParameter("saveCertificate") != null && req.getParameter("saveCertificate").equals("true")){
			r.setSaveCertificate(true);
		}
	}
}
