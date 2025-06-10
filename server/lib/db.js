import mongoose from "mongoose";

export const connectDB = async () => {
  try {
    mongoose.connection.on("connected", () =>
      console.log("Databaase Connected")
    );
    await mongoose.connect(`${process.env.mongoDBUrl}`);
  } catch (e) {
    console.error(error.message);
  }
};
