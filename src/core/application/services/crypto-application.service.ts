/**
 * CryptoApplicationService has been intentionally removed.
 *
 * All managed key operations are handled by their respective use cases (core/application/use-cases/managed/).
 * All stateless crypto operations (legacy routes) are handled directly by CryptoProviderPort
 * in the CryptoController, eliminating a trivial delegation layer with no business logic.
 *
 * @see CryptoController
 * @see ManagedUseCases
 * @see CryptoProviderPort
 */
