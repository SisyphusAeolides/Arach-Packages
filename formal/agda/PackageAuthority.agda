{-# OPTIONS --safe --without-K #-}
module PackageAuthority where

open import Agda.Builtin.Equality using (_≡_; refl)
open import Agda.Builtin.List using (List; []; _∷_)
open import Agda.Builtin.Maybe using (Maybe; just; nothing)

data Scope : Set where
  user system driver firmware : Scope

data Authority : Set where
  arach-native arach-hardware : Authority

data Admitted : Scope → Authority → Set where
  native-user : Admitted user arach-native
  native-system : Admitted system arach-native
  hardware-driver : Admitted driver arach-hardware
  hardware-firmware : Admitted firmware arach-hardware

data ⊥ : Set where

driver-cannot-use-native : Admitted driver arach-native → ⊥
driver-cannot-use-native ()

firmware-cannot-use-native : Admitted firmware arach-native → ⊥
firmware-cannot-use-native ()

system-is-native : (proof : Admitted system arach-native) →
                   proof ≡ native-system
system-is-native native-system = refl

driver-is-hardware : (proof : Admitted driver arach-hardware) →
                     proof ≡ hardware-driver
driver-is-hardware hardware-driver = refl

data Route : Set where
  native rebuilt compatibility-runtime container managed-vm : Route

data Disposition : Set where
  routed : Route → Disposition
  quarantined : Disposition

data Covered : Disposition → Set where
  has-route : {route : Route} → Covered (routed route)
  held-back : Covered quarantined

classify-route : Maybe Route → Disposition
classify-route (just route) = routed route
classify-route nothing = quarantined

coverage-is-total : (candidate : Maybe Route) → Covered (classify-route candidate)
coverage-is-total (just route) = has-route
coverage-is-total nothing = held-back

classify-all : List (Maybe Route) → List Disposition
classify-all [] = []
classify-all (candidate ∷ rest) = classify-route candidate ∷ classify-all rest

data Publishable : Disposition → Set where
  publish-routed : {route : Route} → Publishable (routed route)

quarantine-cannot-publish : Publishable quarantined → ⊥
quarantine-cannot-publish ()
