import { initializeApp } from 'firebase/app';
import {
  getAuth,
  GoogleAuthProvider,
  signInWithPopup,
  signOut,
  onAuthStateChanged,
  type User,
} from 'firebase/auth';
import {
  initializeFirestore,
  doc,
  getDoc,
  getDocFromServer,
  getDocs,
  updateDoc,
  deleteDoc,
  collection,
  query,
  where,
  writeBatch,
  serverTimestamp,
  onSnapshot,
  type Unsubscribe,
} from 'firebase/firestore';
import firebaseConfig from '../firebase-applet-config.json';

const app = initializeApp(firebaseConfig);
export const db = initializeFirestore(
  app,
  { experimentalForceLongPolling: true },
  firebaseConfig.firestoreDatabaseId
);
export const auth = getAuth(app);

export enum OperationType {
  CREATE = 'create',
  UPDATE = 'update',
  DELETE = 'delete',
  LIST = 'list',
  GET = 'get',
  WRITE = 'write',
}

export interface FirestoreErrorInfo {
  error: string;
  operationType: OperationType;
  path: string | null;
  authInfo: {
    userId?: string | null;
    email?: string | null;
    emailVerified?: boolean | null;
    isAnonymous?: boolean | null;
    tenantId?: string | null;
    providerInfo?: {
      providerId?: string | null;
      email?: string | null;
    }[];
  };
}

export function handleFirestoreError(
  error: unknown,
  operationType: OperationType,
  path: string | null
): never {
  const errInfo: FirestoreErrorInfo = {
    error: error instanceof Error ? error.message : String(error),
    authInfo: {
      userId: auth.currentUser?.uid,
      email: auth.currentUser?.email,
      emailVerified: auth.currentUser?.emailVerified,
      isAnonymous: auth.currentUser?.isAnonymous,
      tenantId: auth.currentUser?.tenantId,
      providerInfo:
        auth.currentUser?.providerData?.map((provider) => ({
          providerId: provider.providerId,
          email: provider.email,
        })) || [],
    },
    operationType,
    path,
  };
  console.error('Firestore Error: ', JSON.stringify(errInfo));
  throw new Error(JSON.stringify(errInfo));
}

async function testConnection(): Promise<void> {
  try {
    await getDocFromServer(doc(db, 'test', 'connection'));
  } catch (error) {
    if (error instanceof Error && error.message.includes('the client is offline')) {
      console.error('Please check your Firebase configuration.');
    }
  }
}
void testConnection();

export type AccountType = 'buyer-seller' | 'buyer';

export const ALLOWED_CATEGORIES = [
  'Electronics',
  'Home',
  'Fashion',
  'Books',
  'Deals',
  'Other',
] as const;

export type ProductCategory = (typeof ALLOWED_CATEGORIES)[number];

export interface UserProfile {
  uid: string;
  displayName: string;
  accountType: AccountType;
  photoURL: string;
  createdAt?: unknown;
  updatedAt?: unknown;
}

export interface UserPrivateInfo {
  uid: string;
  email: string;
  updatedAt?: unknown;
}

export interface ProductItem {
  id: string;
  name: string;
  price: number;
  category: ProductCategory;
  description: string;
  image: string;
  sellerId: string;
  sellerName: string;
  status: 'active' | 'archived';
  createdAt?: { seconds?: number; toMillis?: () => number };
}

export interface CartLineItem {
  productId: string;
  name: string;
  price: number;
  quantity?: number;
}

export interface OrderRecord {
  id: string;
  userId: string;
  itemCount: number;
  total: number;
  status: 'placed' | 'completed' | 'cancelled';
  createdAt?: { seconds?: number; toMillis?: () => number };
}

const VALID_ID_REGEX = /^[a-zA-Z0-9_-]+$/;

function sanitizeText(value: unknown, maxLength: number): string {
  return String(value ?? '').trim().slice(0, maxLength);
}

function generateId(prefix: string): string {
  const randomPart =
    typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
      ? crypto.randomUUID().replace(/[^a-zA-Z0-9_-]/g, '')
      : `${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
  const raw = `${prefix}_${randomPart}`.slice(0, 128);
  return VALID_ID_REGEX.test(raw) ? raw : `${prefix}_${Date.now()}`;
}

export function waitForAuthReady(): Promise<User | null> {
  return new Promise((resolve) => {
    const unsubscribe = onAuthStateChanged(auth, (user) => {
      unsubscribe();
      resolve(user);
    });
  });
}

export function observeAuthState(callback: (user: User | null) => void): Unsubscribe {
  return onAuthStateChanged(auth, callback);
}

export async function getUserProfile(uid: string): Promise<UserProfile | null> {
  const path = `users/${uid}`;
  try {
    const snap = await getDoc(doc(db, 'users', uid));
    return snap.exists() ? (snap.data() as UserProfile) : null;
  } catch (error) {
    handleFirestoreError(error, OperationType.GET, path);
  }
}

export async function getUserPrivateInfo(uid: string): Promise<UserPrivateInfo | null> {
  const path = `users/${uid}/private/info`;
  try {
    const snap = await getDoc(doc(db, 'users', uid, 'private', 'info'));
    return snap.exists() ? (snap.data() as UserPrivateInfo) : null;
  } catch (error) {
    handleFirestoreError(error, OperationType.GET, path);
  }
}

export async function ensureUserDocuments(
  user: User,
  preferredAccountType?: AccountType
): Promise<UserProfile> {
  const uid = user.uid;
  if (!VALID_ID_REGEX.test(uid)) {
    throw new Error('Invalid user identifier.');
  }

  const displayName =
    sanitizeText(user.displayName || user.email?.split('@')[0] || 'Shopper', 100) || 'Shopper';
  const email = sanitizeText(user.email || '', 254);
  const photoURL = sanitizeText(user.photoURL || '', 500);
  const accountType: AccountType =
    preferredAccountType === 'buyer' ? 'buyer' : 'buyer-seller';

  const profileRef = doc(db, 'users', uid);
  const privateRef = doc(db, 'users', uid, 'private', 'info');

  let existingSnap;
  try {
    existingSnap = await getDoc(profileRef);
  } catch (error) {
    handleFirestoreError(error, OperationType.GET, `users/${uid}`);
  }

  if (!existingSnap.exists()) {
    const batch = writeBatch(db);
    const profilePayload = {
      uid,
      displayName,
      accountType,
      photoURL,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    };
    batch.set(profileRef, profilePayload);

    if (email.length >= 3) {
      batch.set(privateRef, {
        uid,
        email,
        updatedAt: serverTimestamp(),
      });
    }

    try {
      await batch.commit();
    } catch (error) {
      handleFirestoreError(error, OperationType.WRITE, `users/${uid}`);
    }

    return {
      uid,
      displayName,
      accountType,
      photoURL,
    };
  }

  const existingProfile = existingSnap.data() as UserProfile;
  if (preferredAccountType && existingProfile.accountType !== preferredAccountType) {
    try {
      await updateDoc(profileRef, {
        displayName,
        accountType: preferredAccountType,
        photoURL,
        updatedAt: serverTimestamp(),
      });
      return {
        ...existingProfile,
        displayName,
        accountType: preferredAccountType,
        photoURL,
      };
    } catch (error) {
      handleFirestoreError(error, OperationType.UPDATE, `users/${uid}`);
    }
  }

  return existingProfile;
}

export async function signInWithGoogle(preferredAccountType?: AccountType): Promise<{
  user: User;
  profile: UserProfile;
}> {
  const provider = new GoogleAuthProvider();
  provider.setCustomParameters({ prompt: 'select_account' });

  const credential = await signInWithPopup(auth, provider);
  const profile = await ensureUserDocuments(credential.user, preferredAccountType);

  localStorage.setItem(
    'sulecomUser',
    JSON.stringify({
      uid: credential.user.uid,
      displayName: profile.displayName,
      accountType: profile.accountType,
      email: credential.user.email || '',
    })
  );

  return { user: credential.user, profile };
}

export async function upgradeAccountToSeller(uid: string): Promise<void> {
  const path = `users/${uid}`;
  try {
    await updateDoc(doc(db, 'users', uid), {
      accountType: 'buyer-seller',
      updatedAt: serverTimestamp(),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.UPDATE, path);
  }
}

export async function signOutUser(): Promise<void> {
  localStorage.removeItem('sulecomUser');
  await signOut(auth);
}

export async function fetchActiveProducts(): Promise<ProductItem[]> {
  const path = 'products';
  try {
    const q = query(collection(db, 'products'), where('status', '==', 'active'));
    const snapshot = await getDocs(q);
    return snapshot.docs
      .map((d) => ({ id: d.id, ...(d.data() as Omit<ProductItem, 'id'>) }))
      .sort((a, b) => (b.createdAt?.seconds || 0) - (a.createdAt?.seconds || 0));
  } catch (error) {
    handleFirestoreError(error, OperationType.LIST, path);
  }
}

export function subscribeActiveProducts(
  onData: (items: ProductItem[]) => void,
  onError?: (err: unknown) => void
): Unsubscribe {
  const path = 'products';
  const q = query(collection(db, 'products'), where('status', '==', 'active'));
  return onSnapshot(
    q,
    (snapshot) => {
      const items = snapshot.docs
        .map((d) => ({ id: d.id, ...(d.data() as Omit<ProductItem, 'id'>) }))
        .sort((a, b) => (b.createdAt?.seconds || 0) - (a.createdAt?.seconds || 0));
      onData(items);
    },
    (error) => {
      if (onError) onError(error);
      handleFirestoreError(error, OperationType.LIST, path);
    }
  );
}

export function subscribeSellerProducts(
  sellerId: string,
  onData: (items: ProductItem[]) => void
): Unsubscribe {
  const path = 'products';
  const q = query(collection(db, 'products'), where('sellerId', '==', sellerId));
  return onSnapshot(
    q,
    (snapshot) => {
      const items = snapshot.docs
        .map((d) => ({ id: d.id, ...(d.data() as Omit<ProductItem, 'id'>) }))
        .sort((a, b) => (b.createdAt?.seconds || 0) - (a.createdAt?.seconds || 0));
      onData(items);
    },
    (error) => {
      handleFirestoreError(error, OperationType.LIST, path);
    }
  );
}

export async function createProductListing(input: {
  name: string;
  price: number;
  category: string;
  description: string;
  image?: string;
}): Promise<string> {
  const user = auth.currentUser;
  if (!user) {
    throw new Error('Please sign in to publish products.');
  }

  const profile = await getUserProfile(user.uid);
  if (!profile || profile.accountType !== 'buyer-seller') {
    throw new Error('Only Buy & Sell accounts can publish products.');
  }

  const name = sanitizeText(input.name, 120);
  const price = Number(input.price);
  const category = ALLOWED_CATEGORIES.includes(input.category as ProductCategory)
    ? (input.category as ProductCategory)
    : 'Other';
  const description = sanitizeText(input.description, 1000);
  const image = sanitizeText(
    input.image ||
      'https://images.unsplash.com/photo-1524758631624-e2822e304c36?auto=format&fit=crop&w=900&q=80',
    500
  );
  const sellerName = sanitizeText(profile.displayName || 'Seller', 100) || 'Seller';

  if (!name || !description || !Number.isFinite(price) || price <= 0 || price > 1000000) {
    throw new Error('Please provide a valid product name, price ($0.01 - $1,000,000), and description.');
  }

  const productId = generateId('prod');
  const path = `products/${productId}`;

  try {
    const batch = writeBatch(db);
    batch.set(doc(db, 'products', productId), {
      name,
      price: Number(price.toFixed(2)),
      category,
      description,
      image,
      sellerId: user.uid,
      sellerName,
      status: 'active',
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
    await batch.commit();
    return productId;
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}

export async function deleteProductListing(productId: string): Promise<void> {
  if (!VALID_ID_REGEX.test(productId)) {
    throw new Error('Invalid product identifier.');
  }
  const path = `products/${productId}`;
  try {
    await deleteDoc(doc(db, 'products', productId));
  } catch (error) {
    handleFirestoreError(error, OperationType.DELETE, path);
  }
}

export async function placeOrder(cartItems: CartLineItem[]): Promise<string> {
  const user = auth.currentUser;
  if (!user) {
    throw new Error('Please sign in to place an order.');
  }
  if (!Array.isArray(cartItems) || cartItems.length === 0 || cartItems.length > 50) {
    throw new Error('Cart must contain between 1 and 50 items.');
  }

  const orderId = generateId('ord');
  const orderRef = doc(db, 'orders', orderId);

  const normalizedItems = cartItems.map((item, idx) => {
    const quantity = Math.max(1, Math.min(100, Math.floor(Number(item.quantity || 1))));
    const price = Math.max(0, Math.min(1000000, Number(item.price || 0)));
    return {
      itemId: generateId(`item_${idx}`),
      productId: sanitizeText(item.productId || `item_${idx}`, 128) || `item_${idx}`,
      name: sanitizeText(item.name || 'Marketplace Item', 120) || 'Marketplace Item',
      price: Number(price.toFixed(2)),
      quantity,
    };
  });

  const total = Number(
    normalizedItems.reduce((sum, item) => sum + item.price * item.quantity, 0).toFixed(2)
  );
  if (total <= 0 || total > 10000000) {
    throw new Error('Order total must be greater than $0.00.');
  }

  const batch = writeBatch(db);
  batch.set(orderRef, {
    userId: user.uid,
    itemCount: normalizedItems.length,
    total,
    status: 'placed',
    createdAt: serverTimestamp(),
    updatedAt: serverTimestamp(),
  });

  for (const item of normalizedItems) {
    const itemRef = doc(db, 'orders', orderId, 'items', item.itemId);
    batch.set(itemRef, {
      orderId,
      userId: user.uid,
      productId: item.productId,
      name: item.name,
      price: item.price,
      quantity: item.quantity,
    });
  }

  try {
    await batch.commit();
    return orderId;
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, `orders/${orderId}`);
  }
}

export async function fetchUserOrders(uid: string): Promise<OrderRecord[]> {
  const path = 'orders';
  try {
    const q = query(collection(db, 'orders'), where('userId', '==', uid));
    const snapshot = await getDocs(q);
    return snapshot.docs
      .map((d) => ({ id: d.id, ...(d.data() as Omit<OrderRecord, 'id'>) }))
      .sort((a, b) => (b.createdAt?.seconds || 0) - (a.createdAt?.seconds || 0));
  } catch (error) {
    handleFirestoreError(error, OperationType.LIST, path);
  }
}
