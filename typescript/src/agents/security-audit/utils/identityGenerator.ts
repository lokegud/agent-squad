/**
 * Random Identity Generator
 * Generates complete fictional identities for testing and simulation
 *
 * Includes: name, age, nationality, address, phone, family status,
 * email, personality traits, quirks, history, and ID number
 */

import * as crypto from 'crypto';

// ============================================================================
// Data Sets
// ============================================================================

const FIRST_NAMES_MALE = [
  'James', 'John', 'Robert', 'Michael', 'William', 'David', 'Richard', 'Joseph',
  'Thomas', 'Charles', 'Christopher', 'Daniel', 'Matthew', 'Anthony', 'Mark',
  'Alexander', 'Benjamin', 'Samuel', 'Henry', 'Sebastian', 'Oliver', 'Ethan',
  'Lucas', 'Mason', 'Logan', 'Aiden', 'Jackson', 'Liam', 'Noah', 'Elijah',
  'Viktor', 'Ivan', 'Dmitri', 'Aleksei', 'Nikolai', 'Mikhail', 'Andrei', 'Pavel',
  'Hans', 'Klaus', 'Wolfgang', 'Friedrich', 'Helmut', 'Stefan', 'Markus', 'Tobias',
  'Pierre', 'Jean', 'François', 'Laurent', 'Philippe', 'Michel', 'Olivier', 'Nicolas',
  'Marco', 'Giuseppe', 'Antonio', 'Francesco', 'Alessandro', 'Lorenzo', 'Matteo',
  'Carlos', 'Miguel', 'Juan', 'Pedro', 'José', 'Luis', 'Fernando', 'Rafael',
  'Kenji', 'Hiroshi', 'Takeshi', 'Yuki', 'Ryo', 'Satoshi', 'Kazuki', 'Haruto',
  'Wei', 'Chen', 'Ming', 'Jun', 'Kai', 'Hao', 'Feng', 'Lei'
];

const FIRST_NAMES_FEMALE = [
  'Mary', 'Patricia', 'Jennifer', 'Linda', 'Barbara', 'Elizabeth', 'Susan', 'Jessica',
  'Sarah', 'Karen', 'Nancy', 'Lisa', 'Betty', 'Margaret', 'Sandra', 'Ashley',
  'Emily', 'Emma', 'Olivia', 'Ava', 'Isabella', 'Sophia', 'Mia', 'Charlotte',
  'Amelia', 'Harper', 'Evelyn', 'Abigail', 'Ella', 'Scarlett', 'Grace', 'Chloe',
  'Natasha', 'Anastasia', 'Ekaterina', 'Olga', 'Tatiana', 'Irina', 'Svetlana', 'Marina',
  'Anna', 'Claudia', 'Julia', 'Martina', 'Stefanie', 'Katja', 'Sabine', 'Monika',
  'Marie', 'Sophie', 'Camille', 'Charlotte', 'Isabelle', 'Claire', 'Aurelie', 'Celine',
  'Giulia', 'Francesca', 'Sara', 'Valentina', 'Chiara', 'Elena', 'Lucia', 'Silvia',
  'Maria', 'Carmen', 'Ana', 'Laura', 'Isabel', 'Rosa', 'Elena', 'Sofia',
  'Yuki', 'Sakura', 'Hana', 'Aiko', 'Mei', 'Rin', 'Yuna', 'Saki',
  'Mei', 'Lin', 'Xia', 'Yan', 'Li', 'Hong', 'Fang', 'Ying'
];

const LAST_NAMES = [
  'Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis',
  'Rodriguez', 'Martinez', 'Hernandez', 'Lopez', 'Wilson', 'Anderson', 'Thomas',
  'Taylor', 'Moore', 'Jackson', 'Martin', 'Lee', 'Thompson', 'White', 'Harris',
  'Petrov', 'Ivanov', 'Kuznetsov', 'Sokolov', 'Popov', 'Lebedev', 'Kozlov', 'Novikov',
  'Mueller', 'Schmidt', 'Schneider', 'Fischer', 'Weber', 'Meyer', 'Wagner', 'Becker',
  'Dubois', 'Moreau', 'Laurent', 'Simon', 'Michel', 'Leroy', 'Roux', 'David',
  'Rossi', 'Russo', 'Ferrari', 'Esposito', 'Bianchi', 'Romano', 'Colombo', 'Ricci',
  'Fernandez', 'Gonzalez', 'Sanchez', 'Perez', 'Ramirez', 'Torres', 'Flores', 'Rivera',
  'Tanaka', 'Yamamoto', 'Watanabe', 'Suzuki', 'Takahashi', 'Sato', 'Nakamura', 'Kobayashi',
  'Wang', 'Li', 'Zhang', 'Liu', 'Chen', 'Yang', 'Huang', 'Zhao',
  'Kim', 'Park', 'Lee', 'Choi', 'Jung', 'Kang', 'Cho', 'Yoon'
];

const NATIONALITIES = [
  { code: 'US', name: 'American', country: 'United States' },
  { code: 'GB', name: 'British', country: 'United Kingdom' },
  { code: 'CA', name: 'Canadian', country: 'Canada' },
  { code: 'AU', name: 'Australian', country: 'Australia' },
  { code: 'DE', name: 'German', country: 'Germany' },
  { code: 'FR', name: 'French', country: 'France' },
  { code: 'IT', name: 'Italian', country: 'Italy' },
  { code: 'ES', name: 'Spanish', country: 'Spain' },
  { code: 'NL', name: 'Dutch', country: 'Netherlands' },
  { code: 'SE', name: 'Swedish', country: 'Sweden' },
  { code: 'NO', name: 'Norwegian', country: 'Norway' },
  { code: 'DK', name: 'Danish', country: 'Denmark' },
  { code: 'FI', name: 'Finnish', country: 'Finland' },
  { code: 'PL', name: 'Polish', country: 'Poland' },
  { code: 'RU', name: 'Russian', country: 'Russia' },
  { code: 'JP', name: 'Japanese', country: 'Japan' },
  { code: 'CN', name: 'Chinese', country: 'China' },
  { code: 'KR', name: 'South Korean', country: 'South Korea' },
  { code: 'IN', name: 'Indian', country: 'India' },
  { code: 'BR', name: 'Brazilian', country: 'Brazil' },
  { code: 'MX', name: 'Mexican', country: 'Mexico' },
  { code: 'AR', name: 'Argentinian', country: 'Argentina' },
  { code: 'ZA', name: 'South African', country: 'South Africa' },
  { code: 'NZ', name: 'New Zealander', country: 'New Zealand' },
  { code: 'IE', name: 'Irish', country: 'Ireland' },
  { code: 'CH', name: 'Swiss', country: 'Switzerland' },
  { code: 'AT', name: 'Austrian', country: 'Austria' },
  { code: 'BE', name: 'Belgian', country: 'Belgium' },
  { code: 'PT', name: 'Portuguese', country: 'Portugal' },
  { code: 'GR', name: 'Greek', country: 'Greece' }
];

const CITIES: Record<string, Array<{ city: string; state?: string; zip: string }>> = {
  US: [
    { city: 'New York', state: 'NY', zip: '10001' },
    { city: 'Los Angeles', state: 'CA', zip: '90001' },
    { city: 'Chicago', state: 'IL', zip: '60601' },
    { city: 'Houston', state: 'TX', zip: '77001' },
    { city: 'Phoenix', state: 'AZ', zip: '85001' },
    { city: 'Seattle', state: 'WA', zip: '98101' },
    { city: 'Denver', state: 'CO', zip: '80201' },
    { city: 'Boston', state: 'MA', zip: '02101' }
  ],
  GB: [
    { city: 'London', zip: 'SW1A 1AA' },
    { city: 'Manchester', zip: 'M1 1AD' },
    { city: 'Birmingham', zip: 'B1 1AA' },
    { city: 'Edinburgh', zip: 'EH1 1AA' },
    { city: 'Glasgow', zip: 'G1 1AA' },
    { city: 'Bristol', zip: 'BS1 1AA' }
  ],
  DE: [
    { city: 'Berlin', zip: '10115' },
    { city: 'Munich', zip: '80331' },
    { city: 'Hamburg', zip: '20095' },
    { city: 'Frankfurt', zip: '60311' },
    { city: 'Cologne', zip: '50667' }
  ],
  FR: [
    { city: 'Paris', zip: '75001' },
    { city: 'Lyon', zip: '69001' },
    { city: 'Marseille', zip: '13001' },
    { city: 'Toulouse', zip: '31000' },
    { city: 'Nice', zip: '06000' }
  ],
  JP: [
    { city: 'Tokyo', zip: '100-0001' },
    { city: 'Osaka', zip: '530-0001' },
    { city: 'Kyoto', zip: '600-8001' },
    { city: 'Yokohama', zip: '220-0001' },
    { city: 'Nagoya', zip: '450-0001' }
  ]
};

const STREET_NAMES = [
  'Main', 'Oak', 'Maple', 'Cedar', 'Pine', 'Elm', 'Park', 'Lake',
  'Hill', 'River', 'Forest', 'Spring', 'Valley', 'Meadow', 'Sunset',
  'Highland', 'Washington', 'Lincoln', 'Jefferson', 'Franklin',
  'Church', 'School', 'Market', 'Water', 'Bridge', 'Mill', 'Station'
];

const STREET_TYPES = [
  'Street', 'Avenue', 'Boulevard', 'Road', 'Lane', 'Drive', 'Court',
  'Place', 'Way', 'Circle', 'Terrace', 'Path', 'Parkway'
];

const PERSONALITY_TRAITS = [
  // Positive
  'creative', 'analytical', 'empathetic', 'determined', 'optimistic',
  'patient', 'adventurous', 'loyal', 'charismatic', 'resilient',
  'adaptable', 'curious', 'confident', 'diplomatic', 'generous',
  'honest', 'humble', 'independent', 'innovative', 'intuitive',
  'methodical', 'observant', 'passionate', 'pragmatic', 'resourceful',
  // Neutral
  'introverted', 'extroverted', 'spontaneous', 'cautious', 'competitive',
  'perfectionist', 'idealistic', 'skeptical', 'reserved', 'assertive',
  'meticulous', 'unconventional', 'traditional', 'ambitious', 'laid-back'
];

const QUIRKS = [
  'always carries a lucky charm',
  'speaks to plants',
  'collects unusual keys',
  'knows random historical facts',
  'never forgets a face',
  'always arrives 10 minutes early',
  'has a secret talent for mimicry',
  'obsessed with weather patterns',
  'keeps a journal of dreams',
  'can solve Rubik\'s cube blindfolded',
  'has an encyclopedic knowledge of birds',
  'refuses to use elevators',
  'has synesthesia (sees sounds as colors)',
  'keeps emergency snacks everywhere',
  'practices meditation at sunrise',
  'has a photographic memory for numbers',
  'always eats dessert first',
  'has a collection of vintage maps',
  'can identify any car by sound',
  'writes with both hands equally well',
  'has never missed a deadline',
  'speaks in movie quotes when nervous',
  'has an irrational fear of escalators',
  'always wears mismatched socks intentionally',
  'can recite pi to 100 digits',
  'makes friendship bracelets for stress relief',
  'has an uncanny ability to predict rain',
  'never throws away receipts',
  'always takes the stairs backwards',
  'has named all their household plants'
];

const FAMILY_STATUSES = [
  { status: 'single', description: 'Single, never married' },
  { status: 'married', description: 'Married' },
  { status: 'married_children', description: 'Married with children' },
  { status: 'divorced', description: 'Divorced' },
  { status: 'widowed', description: 'Widowed' },
  { status: 'partnered', description: 'In a domestic partnership' },
  { status: 'engaged', description: 'Engaged' }
];

const OCCUPATIONS = [
  'Software Engineer', 'Teacher', 'Nurse', 'Accountant', 'Marketing Manager',
  'Graphic Designer', 'Sales Representative', 'Project Manager', 'Consultant',
  'Data Analyst', 'Electrician', 'Chef', 'Architect', 'Lawyer', 'Journalist',
  'Pharmacist', 'Physical Therapist', 'Social Worker', 'Financial Advisor',
  'Research Scientist', 'HR Specialist', 'Civil Engineer', 'Psychologist',
  'Veterinarian', 'Real Estate Agent', 'Police Officer', 'Firefighter',
  'Pilot', 'Dentist', 'Photographer', 'Writer', 'Musician', 'Artist'
];

const EDUCATION_LEVELS = [
  'High School Diploma',
  'Associate\'s Degree',
  'Bachelor\'s Degree',
  'Master\'s Degree',
  'Doctorate',
  'Professional Certification',
  'Trade School Certificate'
];

const LIFE_EVENTS = [
  'won a local talent competition',
  'survived a minor natural disaster',
  'traveled to over 20 countries',
  'started a small business',
  'published an article or paper',
  'volunteered abroad for a year',
  'learned a new language as an adult',
  'rescued an abandoned pet',
  'ran a marathon',
  'appeared in a local newspaper',
  'won a scholarship',
  'overcame a significant fear',
  'made a career change',
  'invented a useful household gadget',
  'taught themselves an instrument',
  'organized a community event',
  'survived getting lost in the wilderness',
  'met a celebrity by chance',
  'broke a minor local record',
  'saved money for 5 years to buy dream item'
];

// ============================================================================
// Generator Class
// ============================================================================

export interface GeneratedIdentity {
  id: string;
  firstName: string;
  lastName: string;
  fullName: string;
  gender: 'male' | 'female' | 'non-binary';
  age: number;
  dateOfBirth: Date;
  nationality: {
    code: string;
    name: string;
    country: string;
  };
  address: {
    street: string;
    city: string;
    state?: string;
    zipCode: string;
    country: string;
    full: string;
  };
  phone: string;
  email: string;
  familyStatus: {
    status: string;
    description: string;
    spouseName?: string;
    childrenCount?: number;
  };
  occupation: string;
  education: string;
  personality: {
    traits: string[];
    quirks: string[];
    summary: string;
  };
  history: {
    events: string[];
    narrative: string;
  };
}

export interface GeneratorOptions {
  /** Minimum age */
  minAge?: number;
  /** Maximum age */
  maxAge?: number;
  /** Preferred gender */
  gender?: 'male' | 'female' | 'non-binary' | 'random';
  /** Preferred nationality code */
  nationality?: string;
  /** Seed for reproducible generation */
  seed?: string;
}

export class IdentityGenerator {
  private rng: () => number;

  constructor(seed?: string) {
    if (seed) {
      this.rng = this.seededRandom(seed);
    } else {
      this.rng = Math.random;
    }
  }

  /**
   * Generate a complete random identity
   */
  generate(options?: GeneratorOptions): GeneratedIdentity {
    const gender = options?.gender === 'random' || !options?.gender
      ? (this.rng() > 0.5 ? 'male' : 'female')
      : options.gender;

    const minAge = options?.minAge ?? 18;
    const maxAge = options?.maxAge ?? 80;
    const age = Math.floor(this.rng() * (maxAge - minAge + 1)) + minAge;

    const firstName = this.randomFrom(
      gender === 'male' ? FIRST_NAMES_MALE :
      gender === 'female' ? FIRST_NAMES_FEMALE :
      [...FIRST_NAMES_MALE, ...FIRST_NAMES_FEMALE]
    );
    const lastName = this.randomFrom(LAST_NAMES);

    const nationality = options?.nationality
      ? NATIONALITIES.find(n => n.code === options.nationality) || this.randomFrom(NATIONALITIES)
      : this.randomFrom(NATIONALITIES);

    const address = this.generateAddress(nationality.code);
    const phone = this.generatePhone(nationality.code);
    const email = this.generateEmail(firstName, lastName);
    const familyStatus = this.generateFamilyStatus(age, gender);
    const personality = this.generatePersonality();
    const history = this.generateHistory(age, nationality.name, familyStatus.status);

    const id = this.generateId();

    const dob = new Date();
    dob.setFullYear(dob.getFullYear() - age);
    dob.setMonth(Math.floor(this.rng() * 12));
    dob.setDate(Math.floor(this.rng() * 28) + 1);

    return {
      id,
      firstName,
      lastName,
      fullName: `${firstName} ${lastName}`,
      gender: gender as 'male' | 'female' | 'non-binary',
      age,
      dateOfBirth: dob,
      nationality,
      address,
      phone,
      email,
      familyStatus,
      occupation: this.randomFrom(OCCUPATIONS),
      education: this.randomFrom(EDUCATION_LEVELS),
      personality,
      history
    };
  }

  /**
   * Generate multiple identities
   */
  generateBatch(count: number, options?: GeneratorOptions): GeneratedIdentity[] {
    return Array.from({ length: count }, () => this.generate(options));
  }

  /**
   * Generate a 9-digit ID number
   */
  generateId(): string {
    return Array.from({ length: 9 }, () =>
      Math.floor(this.rng() * 10).toString()
    ).join('');
  }

  /**
   * Generate an address
   */
  private generateAddress(countryCode: string): GeneratedIdentity['address'] {
    const cityData = CITIES[countryCode] || CITIES['US'];
    const location = this.randomFrom(cityData);

    const streetNum = Math.floor(this.rng() * 9999) + 1;
    const streetName = this.randomFrom(STREET_NAMES);
    const streetType = this.randomFrom(STREET_TYPES);

    const street = `${streetNum} ${streetName} ${streetType}`;
    const country = NATIONALITIES.find(n => n.code === countryCode)?.country || 'United States';

    const full = location.state
      ? `${street}, ${location.city}, ${location.state} ${location.zip}, ${country}`
      : `${street}, ${location.city} ${location.zip}, ${country}`;

    return {
      street,
      city: location.city,
      state: location.state,
      zipCode: location.zip,
      country,
      full
    };
  }

  /**
   * Generate a phone number
   */
  private generatePhone(countryCode: string): string {
    const formats: Record<string, string> = {
      US: '+1 (XXX) XXX-XXXX',
      GB: '+44 XXXX XXXXXX',
      DE: '+49 XXX XXXXXXXX',
      FR: '+33 X XX XX XX XX',
      JP: '+81 XX-XXXX-XXXX',
      AU: '+61 X XXXX XXXX',
      CA: '+1 (XXX) XXX-XXXX'
    };

    const format = formats[countryCode] || formats['US'];
    return format.replace(/X/g, () => Math.floor(this.rng() * 10).toString());
  }

  /**
   * Generate an email address
   */
  private generateEmail(firstName: string, lastName: string): string {
    const domains = [
      'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
      'protonmail.com', 'icloud.com', 'mail.com'
    ];

    const formats = [
      `${firstName.toLowerCase()}.${lastName.toLowerCase()}`,
      `${firstName.toLowerCase()}${lastName.toLowerCase()}`,
      `${firstName.toLowerCase()}_${lastName.toLowerCase()}`,
      `${firstName[0].toLowerCase()}${lastName.toLowerCase()}`,
      `${firstName.toLowerCase()}${Math.floor(this.rng() * 100)}`
    ];

    const localPart = this.randomFrom(formats);
    const domain = this.randomFrom(domains);

    return `${localPart}@${domain}`;
  }

  /**
   * Generate family status
   */
  private generateFamilyStatus(
    age: number,
    gender: string
  ): GeneratedIdentity['familyStatus'] {
    // Adjust probabilities based on age
    let status: typeof FAMILY_STATUSES[0];

    if (age < 25) {
      status = this.rng() > 0.8
        ? FAMILY_STATUSES.find(s => s.status === 'partnered')!
        : FAMILY_STATUSES.find(s => s.status === 'single')!;
    } else if (age < 35) {
      const rand = this.rng();
      if (rand < 0.3) status = FAMILY_STATUSES.find(s => s.status === 'single')!;
      else if (rand < 0.5) status = FAMILY_STATUSES.find(s => s.status === 'partnered')!;
      else if (rand < 0.7) status = FAMILY_STATUSES.find(s => s.status === 'engaged')!;
      else status = FAMILY_STATUSES.find(s => s.status === 'married')!;
    } else {
      const rand = this.rng();
      if (rand < 0.15) status = FAMILY_STATUSES.find(s => s.status === 'single')!;
      else if (rand < 0.3) status = FAMILY_STATUSES.find(s => s.status === 'divorced')!;
      else if (rand < 0.35 && age > 60) status = FAMILY_STATUSES.find(s => s.status === 'widowed')!;
      else status = FAMILY_STATUSES.find(s => s.status === 'married_children')!;
    }

    const result: GeneratedIdentity['familyStatus'] = {
      status: status.status,
      description: status.description
    };

    // Add spouse for married/partnered
    if (['married', 'married_children', 'partnered', 'engaged'].includes(status.status)) {
      const spouseFirstName = this.randomFrom(
        gender === 'male' ? FIRST_NAMES_FEMALE : FIRST_NAMES_MALE
      );
      result.spouseName = spouseFirstName;
    }

    // Add children for married_children
    if (status.status === 'married_children') {
      result.childrenCount = Math.floor(this.rng() * 4) + 1;
    }

    return result;
  }

  /**
   * Generate personality traits and quirks
   */
  private generatePersonality(): GeneratedIdentity['personality'] {
    const traits = this.randomSample(PERSONALITY_TRAITS, 5);
    const quirks = this.randomSample(QUIRKS, 2);

    const summary = `A ${traits[0]} and ${traits[1]} individual who is known for being ${traits[2]}. ` +
      `Friends describe them as ${traits[3]} with a ${traits[4]} nature. ` +
      `They have a peculiar habit: ${quirks[0].toLowerCase()}. Also, ${quirks[1].toLowerCase()}.`;

    return { traits, quirks, summary };
  }

  /**
   * Generate life history
   */
  private generateHistory(
    age: number,
    nationality: string,
    familyStatus: string
  ): GeneratedIdentity['history'] {
    const eventCount = Math.min(Math.floor(age / 10), 5);
    const events = this.randomSample(LIFE_EVENTS, eventCount);

    // Build narrative
    const narrative = this.buildNarrative(age, nationality, familyStatus, events);

    return { events, narrative };
  }

  /**
   * Build a narrative from history elements
   */
  private buildNarrative(
    age: number,
    nationality: string,
    familyStatus: string,
    events: string[]
  ): string {
    const birthDecade = Math.floor((new Date().getFullYear() - age) / 10) * 10;

    let narrative = `Born in the ${birthDecade}s to a ${nationality} family. `;

    if (age >= 20) {
      narrative += `During their formative years, they ${events[0] || 'developed a passion for learning'}. `;
    }

    if (age >= 30 && events.length > 1) {
      narrative += `In their twenties, they ${events[1]}. `;
    }

    if (age >= 40 && events.length > 2) {
      narrative += `A defining moment came when they ${events[2]}. `;
    }

    if (familyStatus === 'married_children') {
      narrative += 'Family became a central focus of their life. ';
    } else if (familyStatus === 'divorced') {
      narrative += 'They experienced significant personal changes in their relationships. ';
    }

    if (events.length > 3) {
      narrative += `More recently, they ${events[3]}. `;
    }

    narrative += 'These experiences have shaped who they are today.';

    return narrative;
  }

  /**
   * Select random item from array
   */
  private randomFrom<T>(array: T[]): T {
    return array[Math.floor(this.rng() * array.length)];
  }

  /**
   * Select random sample from array (no duplicates)
   */
  private randomSample<T>(array: T[], count: number): T[] {
    const shuffled = [...array].sort(() => this.rng() - 0.5);
    return shuffled.slice(0, count);
  }

  /**
   * Create seeded random number generator
   */
  private seededRandom(seed: string): () => number {
    const hash = crypto.createHash('sha256').update(seed).digest();
    let index = 0;

    return () => {
      const value = hash.readUInt32BE(index % (hash.length - 4)) / 0xffffffff;
      index = (index + 4) % hash.length;
      return value;
    };
  }

  /**
   * Format identity as string
   */
  static format(identity: GeneratedIdentity, format: 'full' | 'brief' | 'json' = 'full'): string {
    if (format === 'json') {
      return JSON.stringify(identity, null, 2);
    }

    if (format === 'brief') {
      return `${identity.fullName} (${identity.age}, ${identity.nationality.name}) - ID: ${identity.id}`;
    }

    return `
═══════════════════════════════════════════════════════════════
                      IDENTITY PROFILE
═══════════════════════════════════════════════════════════════

ID Number:      ${identity.id}
Full Name:      ${identity.fullName}
Gender:         ${identity.gender}
Age:            ${identity.age}
Date of Birth:  ${identity.dateOfBirth.toLocaleDateString()}
Nationality:    ${identity.nationality.name} (${identity.nationality.country})

───────────────────────────────────────────────────────────────
                        CONTACT
───────────────────────────────────────────────────────────────

Address:        ${identity.address.full}
Phone:          ${identity.phone}
Email:          ${identity.email}

───────────────────────────────────────────────────────────────
                      PERSONAL
───────────────────────────────────────────────────────────────

Family Status:  ${identity.familyStatus.description}
${identity.familyStatus.spouseName ? `Spouse:         ${identity.familyStatus.spouseName}` : ''}
${identity.familyStatus.childrenCount ? `Children:       ${identity.familyStatus.childrenCount}` : ''}

Occupation:     ${identity.occupation}
Education:      ${identity.education}

───────────────────────────────────────────────────────────────
                      PERSONALITY
───────────────────────────────────────────────────────────────

Traits:         ${identity.personality.traits.join(', ')}

Quirks:
  • ${identity.personality.quirks.join('\n  • ')}

Summary:
${identity.personality.summary}

───────────────────────────────────────────────────────────────
                        HISTORY
───────────────────────────────────────────────────────────────

${identity.history.narrative}

Notable events:
  • ${identity.history.events.join('\n  • ')}

═══════════════════════════════════════════════════════════════
`.trim();
  }
}

export default IdentityGenerator;
